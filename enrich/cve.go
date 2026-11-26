package enrich

// Engine-side CVE enrichment: a version fingerprint (whatweb-style technology
// entry or an HTTP response header) is mapped to public exploit candidates
// WITHOUT burning an LLM turn. Offline-first: the Exploit-DB CSV shipped by the
// kali exploitdb package is parsed and matched locally, so the layer works with
// no internet at all. Online sources are fail-soft and cached: CISA KEV
// (exploited-in-the-wild flag), FIRST EPSS (prioritisation score) and — only
// when the local DB yields nothing — an NVD keyword search (unauthenticated
// budget: 5 requests / 30 s, enforced locally).
//
// Results land on the asset as extra.cve (shallow-merged JSONB) and are visible
// to workers/planner through list_assets. They are CANDIDATES, not findings:
// the exploit-search skill owns the applicability gate (version range + advisory
// line quoted) before anything is claimed or run.
//
// Env toggles (read once at engine start):
//
//	ARTEX_CVE_ENRICH=0   disable the whole layer
//	ARTEX_CVE_ONLINE=0   local Exploit-DB only, no outbound feed lookups
//	ARTEX_CVE_EDB_CSV   path override (default /usr/share/exploitdb/files_exploits.csv)

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

func envBool(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envStr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// fingerprints
// ---------------------------------------------------------------------------

type fingerprint struct {
	Product string // normalized: lowercase, single-space separated words
	Version string // dotted decimal, e.g. 1.18.0
}

var (
	// explicit separator: nginx/1.18.0, PHP/7.4.33, Microsoft-IIS/10.0,
	// Nginx[1.18.0] (whatweb), Apache:2.4.49
	reFpDelim = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+#._-]{1,28}(?:[ _][a-z0-9+#._-]{1,28}){0,2})\s*[\[/:\\]\s*v?(\d+(?:\.\d+){0,3})`)
	// space separated: "Apache 2.4.49", "Nginx 1.18.0" — require a dotted
	// version so natural text ("error 404", "port 8080") does not fire
	reFpSpace = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+#._-]{2,28}(?:[ _][a-z0-9+#._-]{2,28}){0,2})\s+v?(\d+(?:\.\d+){1,3})`)
	// product tokens that are never a product
	fpStopwords = map[string]bool{
		"v": true, "ver": true, "version": true, "build": true, "release": true,
		"http": true, "https": true, "error": true, "code": true, "status": true,
		"port": true, "size": true, "length": true, "id": true, "part": true,
		"rfc": true, "no": true,
	}
)

// reSSHProtoPrefix strips the protocol banner prefix ("SSH-2.0-OpenSSH_8.9p1"
// → "OpenSSH_8.9p1") so the product token does not swallow the protocol version.
var reSSHProtoPrefix = regexp.MustCompile(`(?i)\b(?:ssh|ftp|smtp|imap|pop3?)-\d+(?:\.\d+)?-`)

// parseFingerprints extracts (product, version) pairs from whatweb/wappalyzer
// style technology strings, raw HTTP headers, or service banners
// ("SSH-2.0-OpenSSH_8.9p1", "MySQL 5.7.29-log", "220 ProFTPD 1.3.5b Server").
// Deduped, capped.
func parseFingerprints(in string) []fingerprint {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	// banner normalisation: drop the protocol prefix, treat underscores as
	// separators (OpenSSH_8.9p1 → "OpenSSH 8.9p1")
	in = reSSHProtoPrefix.ReplaceAllString(in, " ")
	in = strings.ReplaceAll(in, "_", " ")
	var out []fingerprint
	seen := map[string]bool{}
	add := func(product, version string) {
		product = normalizeProduct(product)
		if product == "" || fpStopwords[strings.Fields(product)[0]] {
			return
		}
		if len(strings.Fields(product)) > 3 { // natural sentence, not a tech name
			return
		}
		key := product + "|" + version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fingerprint{Product: product, Version: version})
	}
	for _, m := range reFpDelim.FindAllStringSubmatch(in, -1) {
		add(m[1], m[2])
	}
	for _, m := range reFpSpace.FindAllStringSubmatch(in, -1) {
		add(m[1], m[2])
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func normalizeProduct(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	// hyphens/underscores separate words so "Microsoft-IIS" matches the
	// "Microsoft IIS 10.0 ..." wording used in exploit descriptions
	p = strings.NewReplacer("-", " ", "_", " ").Replace(p)
	p = strings.Join(strings.Fields(p), " ")
	return strings.Trim(p, ".")
}

// ---------------------------------------------------------------------------
// candidates
// ---------------------------------------------------------------------------

// cveCandidate is one exploit hint attached to the asset. EDB is the
// searchsploit id (inspect with `searchsploit -x`); CVE (when present) is what
// KEV/EPSS key on.
type cveCandidate struct {
	Product  string  `json:"product"`
	Version  string  `json:"version"`
	CVE      string  `json:"cve,omitempty"`
	EDB      string  `json:"edb,omitempty"`
	Title    string  `json:"title"`
	Type     string  `json:"type,omitempty"`    // webapps / remote / local
	Platform string  `json:"platform,omitempty"`
	Verified bool    `json:"verified,omitempty"`
	KEV      bool    `json:"kev,omitempty"`     // CISA known-exploited
	EPSS     float64 `json:"epss,omitempty"`    // FIRST EPSS probability, 0..1
	Source   string  `json:"source"`            // edb | nvd
}

// ---------------------------------------------------------------------------
// Exploit-DB local index
// ---------------------------------------------------------------------------

type edbRow struct {
	id        string
	desc      string // lowercase
	typ       string
	platform  string
	verified  bool
	codes     []string // CVE ids referenced by the entry
	updated   string
	versions  []string // every dotted-decimal token in desc, exact-match set
	ranges    [][2]string // affected ranges parsed from desc ("1.9.14 - 1.20.0", "before 1.20.1")
}

const edbRefresh = 12 * time.Hour

// loadEDB parses the exploitdb CSV once (and re-checks every edbRefresh). The
// header row is indexed by name so column drift between kali releases is
// tolerated. Missing file → the layer simply runs online-only.
func (c *cveEnricher) loadEDB() []edbRow {
	c.edbMu.Lock()
	defer c.edbMu.Unlock()
	if c.edbRows != nil && time.Since(c.edbLoaded) < edbRefresh {
		return c.edbRows
	}
	f, err := os.Open(c.edbPath)
	if err != nil {
		if !c.edbWarned {
			log.Printf("[enrich] exploit-db CSV недоступен (%s): локальный поиск CVE выключен, онлайн-источники продолжают работать: %v", c.edbPath, err)
			c.edbWarned = true
		}
		return nil
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(rec []string, name string) string {
		if i, ok := idx[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	var rows []edbRow
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) == 0 {
			continue
		}
		typ := strings.ToLower(get(rec, "type"))
		if typ == "dos" { // availability-impacting class excluded at search time
			continue
		}
		desc := strings.ToLower(get(rec, "description"))
		row := edbRow{
			id:       get(rec, "id"),
			desc:     desc,
			typ:      typ,
			platform: strings.ToLower(get(rec, "platform")),
			verified: get(rec, "verified") == "1",
			updated:  get(rec, "date_updated"),
			versions: versionTokens(desc),
			ranges:   versionRanges(desc),
		}
		for _, code := range strings.FieldsFunc(get(rec, "codes"), func(r rune) bool { return r == ';' || r == ',' }) {
			if code = strings.TrimSpace(code); strings.HasPrefix(strings.ToUpper(code), "CVE-") {
				row.codes = append(row.codes, strings.ToUpper(code))
			}
		}
		rows = append(rows, row)
	}
	c.edbRows, c.edbLoaded, c.edbWarned = rows, time.Now(), false
	log.Printf("[enrich] exploit-db индекс загружен: %d строк (dos исключены)", len(rows))
	return rows
}

var reVersionToken = regexp.MustCompile(`\d+(?:\.\d+){0,3}`)

func versionTokens(lowerDesc string) []string {
	var out []string
	for _, m := range reVersionToken.FindAllString(lowerDesc, -1) {
		out = append(out, m)
	}
	return out
}

// Affected-range syntaxes seen in exploit descriptions: "1.3.9 < 1.4.0",
// "1.9.14 - 1.20.0", "x before 1.20.1", bare "< 1.21.0". Ranges are inclusive
// at both ends — they generate hints, the applicability gate is downstream.
var (
	reVerPair   = regexp.MustCompile(`(\d+(?:\.\d+){1,3})\s*(?:<=?|–|—|\s-\s|to|through|bis)\s*(\d+(?:\.\d+){1,3})`)
	reVerBefore = regexp.MustCompile(`(?:before|prior to|up to)\s+(\d+(?:\.\d+){1,3})`)
	reVerLess   = regexp.MustCompile(`<=?\s*(\d+(?:\.\d+){1,3})`)
)

func versionRanges(lowerDesc string) [][2]string {
	var out [][2]string
	// pair spans first, so the open-start patterns can skip what they'd duplicate
	var pairSpans [][2]int
	for _, m := range reVerPair.FindAllStringSubmatchIndex(lowerDesc, -1) {
		out = append(out, [2]string{lowerDesc[m[2]:m[3]], lowerDesc[m[4]:m[5]]})
		pairSpans = append(pairSpans, [2]int{m[0], m[1]})
	}
	inPair := func(start int) bool {
		for _, s := range pairSpans {
			if start >= s[0] && start < s[1] {
				return true
			}
		}
		return false
	}
	for _, m := range reVerBefore.FindAllStringSubmatchIndex(lowerDesc, -1) {
		if !inPair(m[0]) {
			out = append(out, [2]string{"0", lowerDesc[m[2]:m[3]]})
		}
	}
	for _, m := range reVerLess.FindAllStringSubmatchIndex(lowerDesc, -1) {
		if !inPair(m[0]) {
			out = append(out, [2]string{"0", lowerDesc[m[2]:m[3]]})
		}
	}
	return out
}

// compareVersions is numeric component-wise ("1.4" < "1.14"), zero-padded
// ("1.18" == "1.18.0").
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// containsVersion reports whether the row plausibly affects version v: an
// exact token match ("1.18.0" in the description) or containment in a parsed
// affected range ("1.9.14 - 1.20.0" contains it).
func (r *edbRow) containsVersion(v string) bool {
	for _, t := range r.versions {
		if t == v {
			return true
		}
	}
	for _, rg := range r.ranges {
		if compareVersions(v, rg[0]) >= 0 && compareVersions(v, rg[1]) <= 0 {
			return true
		}
	}
	return false
}

// productWordsMatch requires every word of the (normalized) product to appear
// as a word in the description: "microsoft iis" matches "Microsoft IIS 10.0
// Remote Code Execution", "iis" alone also matches, "nginx-http" → {"nginx",
// "http"}… stopwords already filtered upstream.
func productWordsMatch(desc, product string) bool {
	words := strings.Fields(product)
	if len(words) == 0 {
		return false
	}
	// cheap prefilter on the first word
	if !strings.Contains(desc, words[0]) {
		return false
	}
	toks := map[string]bool{}
	for _, t := range strings.FieldsFunc(desc, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '#' || r == '.' || r == '-')
	}) {
		toks[t] = true
	}
	for _, w := range words {
		if !toks[w] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// online feeds (all fail-soft)
// ---------------------------------------------------------------------------

const (
	kevURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL  = "https://api.first.org/data/v1/epss" // NB: /epss is the HTML docs page; the data API lives under /data/v1
	nvdURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdWindow = 30 * time.Second
	nvdBurst  = 5
)

// ---------------------------------------------------------------------------
// enricher
// ---------------------------------------------------------------------------

type cveEnricher struct {
	enabled bool
	online  bool
	edbPath string
	client  *http.Client // direct: vulnerability feeds are not target traffic and must not land in the traffic store

	edbMu     sync.Mutex
	edbRows   []edbRow
	edbLoaded time.Time
	edbWarned bool

	fpCache sync.Map // "product|version" -> []cveCandidate

	kevMu  sync.Mutex
	kevSet map[string]bool
	kevAt  time.Time

	epssCache sync.Map // CVE id -> float64

	// NVD unauthenticated budget: at most nvdBurst calls per rolling nvdWindow.
	nvdMu   sync.Mutex
	nvdTimes []time.Time

	// overridable in tests
	kev, epss, nvd string
}

func newCVEEnricher() *cveEnricher {
	return &cveEnricher{
		enabled: envBool("ARTEX_CVE_ENRICH", true),
		online:  envBool("ARTEX_CVE_ONLINE", true),
		edbPath: envStr("ARTEX_CVE_EDB_CSV", "/usr/share/exploitdb/files_exploits.csv"),
		client:  &http.Client{Timeout: 15 * time.Second},
		kev:     kevURL,
		epss:    epssURL,
		nvd:     nvdURL,
	}
}

// research maps a raw fingerprint string to a ranked, capped candidate list.
func (c *cveEnricher) research(fingerprintStr string) []cveCandidate {
	if c == nil || !c.enabled {
		return nil
	}
	fps := parseFingerprints(fingerprintStr)
	if len(fps) == 0 {
		return nil
	}
	var all []cveCandidate
	for _, fp := range fps {
		all = append(all, c.lookup(fp)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].KEV != all[j].KEV {
			return all[i].KEV
		}
		if all[i].EPSS != all[j].EPSS {
			return all[i].EPSS > all[j].EPSS
		}
		if all[i].Verified != all[j].Verified {
			return all[i].Verified
		}
		return all[i].CVE > all[j].CVE
	})
	if len(all) > 8 {
		all = all[:8]
	}
	return all
}

func (c *cveEnricher) lookup(fp fingerprint) []cveCandidate {
	key := fp.Product + "|" + fp.Version
	if v, ok := c.fpCache.Load(key); ok {
		cands, _ := v.([]cveCandidate)
		return cands
	}
	cands := c.localEDB(fp)
	if len(cands) == 0 && c.online {
		cands = c.nvdProduct(fp)
	}
	if len(cands) > 0 && c.online {
		c.tagOnline(cands)
	}
	c.fpCache.Store(key, cands)
	return cands
}

// localEDB matches the fingerprint against the local Exploit-DB index.
func (c *cveEnricher) localEDB(fp fingerprint) []cveCandidate {
	rows := c.loadEDB()
	if len(rows) == 0 {
		return nil
	}
	version := strings.TrimPrefix(fp.Version, "v")
	var hits []edbRow
	for _, row := range rows {
		if !productWordsMatch(row.desc, fp.Product) || !row.containsVersion(version) {
			continue
		}
		hits = append(hits, row)
		if len(hits) >= 12 {
			break
		}
	}
	// verified entries first, most recently updated win ties
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].verified != hits[j].verified {
			return hits[i].verified
		}
		return hits[i].updated > hits[j].updated
	})
	out := make([]cveCandidate, 0, len(hits))
	for _, row := range hits {
		cand := cveCandidate{
			Product:  fp.Product,
			Version:  fp.Version,
			EDB:      row.id,
			Title:    row.desc,
			Type:     row.typ,
			Platform: row.platform,
			Verified: row.verified,
			Source:   "edb",
		}
		if len(row.codes) > 0 {
			cand.CVE = row.codes[0]
		}
		out = append(out, cand)
	}
	return out
}

// tagOnline annotates candidates with KEV / EPSS in place.
func (c *cveEnricher) tagOnline(cands []cveCandidate) {
	kev := c.loadKEV()
	ids := make([]string, 0, len(cands))
	seen := map[string]bool{}
	for _, cand := range cands {
		if cand.CVE != "" && !seen[cand.CVE] {
			seen[cand.CVE] = true
			ids = append(ids, cand.CVE)
		}
	}
	epss := c.epssBatch(ids)
	for i := range cands {
		if cands[i].CVE == "" {
			continue
		}
		if kev[cands[i].CVE] {
			cands[i].KEV = true
		}
		if s, ok := epss[cands[i].CVE]; ok {
			cands[i].EPSS = s
		}
	}
}

func (c *cveEnricher) loadKEV() map[string]bool {
	c.kevMu.Lock()
	defer c.kevMu.Unlock()
	if c.kevSet != nil && time.Since(c.kevAt) < time.Hour {
		return c.kevSet
	}
	set := map[string]bool{}
	if body, err := c.get(c.kev); err == nil {
		var feed struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(body, &feed) == nil {
			for _, v := range feed.Vulnerabilities {
				if v.CVEID != "" {
					set[strings.ToUpper(v.CVEID)] = true
				}
			}
		}
	}
	if len(set) > 0 {
		c.kevSet, c.kevAt = set, time.Now()
	}
	return set
}

func (c *cveEnricher) epssBatch(ids []string) map[string]float64 {
	out := map[string]float64{}
	var missing []string
	for _, id := range ids {
		if v, ok := c.epssCache.Load(id); ok {
			if s, ok := v.(float64); ok {
				out[id] = s
				continue
			}
		}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return out
	}
	// one GET carries a comma-joined cve list (docs cap the param at 2000 chars)
	for len(missing) > 0 {
		batch := missing
		if len(batch) > 80 {
			batch = batch[:80]
		}
		missing = missing[len(batch):]
		url := c.epss + "?cve=" + strings.Join(batch, ",")
		body, err := c.get(url)
		if err != nil {
			continue // fail-soft: candidates simply carry no EPSS
		}
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &resp) != nil {
			continue
		}
		for _, d := range resp.Data {
			if s, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				c.epssCache.Store(d.CVE, s)
				out[d.CVE] = s
			}
		}
	}
	return out
}

// cpeProducts maps normalized fingerprint products to their exact CPE 2.3
// (vendor, product) pair where the tokens differ from the colloquial name.
// Matching is equality-based: a "nginx" fingerprint must NOT match the CPE of
// nginx-ui / Nginx Proxy Manager / nginx-ingress (different products whose
// names merely contain "nginx").
var cpeProducts = map[string][2]string{
	"nginx":             {"f5", "nginx"}, // NVD lists nginx under its owner F5
	"apache":            {"apache", "http_server"},
	"apache httpd":      {"apache", "http_server"},
	"apache http server": {"apache", "http_server"},
	"microsoft iis":     {"microsoft", "internet_information_services"},
	"iis":               {"microsoft", "internet_information_services"},
	"internet information services": {"microsoft", "internet_information_services"},
	"tomcat":            {"apache", "tomcat"},
	"apache tomcat":     {"apache", "tomcat"},
	"struts":            {"apache", "struts"},
	"apache struts":     {"apache", "struts"},
	"wordpress":         {"wordpress", "wordpress"},
	"php":               {"php", "php"},
	"mysql":             {"oracle", "mysql"},
	"mariadb":           {"mariadb", "mariadb"},
	"postgresql":        {"postgresql", "postgresql"},
	"redis":             {"redis", "redis"},
	"mongodb":           {"mongodb", "mongodb"},
	"jenkins":           {"jenkins", "jenkins"},
	"confluence":        {"atlassian", "confluence_server"},
	"gitlab":            {"gitlab", "gitlab"},
	"grafana":           {"grafana", "grafana"},
	"exim":              {"exim", "exim"},
	"openssh":           {"openbsd", "openssh"},
	"dropbear":          {"matt_johnston", "dropbear_ssh_server"},
	"dovecot":           {"dovecot", "dovecot"},
}

func cpeNormalize(s string) string {
	var b []byte
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b = append(b, byte(r))
		}
	}
	return string(b)
}

// cpeProductMatch reports whether the fingerprint product corresponds to the
// CPE criteria (vendor, product). Known products match their mapped pair
// exactly; unknown products require normalized product-token equality so that
// e.g. "nginx" never matches "nginx_ui" or "nginx_proxy_manager".
func cpeProductMatch(fpProduct, cpeVendor, cpeProduct string) bool {
	if mapped, ok := cpeProducts[fpProduct]; ok {
		return cpeNormalize(mapped[0]) == cpeNormalize(cpeVendor) &&
			cpeNormalize(mapped[1]) == cpeNormalize(cpeProduct)
	}
	return cpeNormalize(fpProduct) == cpeNormalize(cpeProduct) && cpeProduct != ""
}

// parseCPE splits "cpe:2.3:a:vendor:product:version:..." into vendor/product/
// version. Indices after Split(":"): 0=cpe 1=2.3 2=a 3=vendor 4=product 5=version.
func parseCPE(cpe string) (vendor, product, version string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 || parts[0] != "cpe" {
		return "", "", ""
	}
	return parts[3], parts[4], parts[5]
}

// nvdProduct queries NVD by product keyword and filters client-side against
// the fingerprint version using the CPE criteria ranges. Candidates are
// marked source:"nvd" — the applicability gate in the skill still applies.
func (c *cveEnricher) nvdProduct(fp fingerprint) []cveCandidate {
	var out []cveCandidate
	for page := 0; page < 3; page++ { // ≤3 pages: protects the unauth budget
		if !c.nvdAllow() {
			return out
		}
		url := fmt.Sprintf("%s?keywordSearch=%s&startIndex=%d", c.nvd, fp.Product, page*2000)
		body, err := c.get(url)
		if err != nil {
			return out
		}
		var resp nvdResponse
		if json.Unmarshal(body, &resp) != nil {
			return out
		}
		for _, v := range resp.Vulnerabilities {
			if !nvdVersionInRange(v, fp) {
				continue
			}
			cand := cveCandidate{
				Product: fp.Product,
				Version: fp.Version,
				CVE:     v.CVE.ID,
				Source:  "nvd",
			}
			for _, d := range v.CVE.Descriptions {
				if d.Lang == "en" {
					cand.Title = d.Value
					break
				}
			}
			if len(v.CVE.Metrics.CvssMetricV31) > 0 {
				cand.Type = "cvss:" + v.CVE.Metrics.CvssMetricV31[0].CVSSData.BaseSeverity
			}
			out = append(out, cand)
			if len(out) >= 8 {
				return out
			}
		}
		if len(resp.Vulnerabilities) == 0 || resp.StartIndex+len(resp.Vulnerabilities) >= resp.TotalResults {
			break
		}
	}
	return out
}

type nvdVuln struct {
	CVE struct {
		ID           string `json:"id"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CvssMetricV31 []struct {
				CVSSData struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Vulnerable            bool   `json:"vulnerable"`
					Criteria              string `json:"criteria"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionStartExcluding string `json:"versionStartExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

type nvdResponse struct {
	TotalResults    int        `json:"totalResults"`
	StartIndex      int        `json:"startIndex"`
	Vulnerabilities []nvdVuln  `json:"vulnerabilities"`
}

// nvdVersionInRange checks the fingerprint (product, version) against the
// CVE's CPE criteria. A criteria matches when the product corresponds AND the
// version satisfies its bounds: concrete criteria version = equality,
// "*" = the versionStart/versionEnd bounds (zero-padded numeric compare).
func nvdVersionInRange(v nvdVuln, fp fingerprint) bool {
	for _, cfg := range v.CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				vendor, product, cpeVer := parseCPE(m.Criteria)
				if !cpeProductMatch(fp.Product, vendor, product) {
					continue
				}
				if cpeVer != "" && cpeVer != "*" {
					if compareVersions(cpeVer, fp.Version) == 0 {
						return true
					}
					continue
				}
				lo, hi := "", ""
				if m.VersionStartIncluding != "" {
					lo = m.VersionStartIncluding
				} else if m.VersionStartExcluding != "" {
					lo = m.VersionStartExcluding
				}
				if m.VersionEndIncluding != "" {
					hi = m.VersionEndIncluding
				} else if m.VersionEndExcluding != "" {
					hi = m.VersionEndExcluding
				}
				if lo == "" && hi == "" {
					continue // unbounded criteria: no version signal, skip
				}
				if lo != "" {
					c := compareVersions(fp.Version, lo)
					if m.VersionStartExcluding != "" && c <= 0 {
						continue
					}
					if c < 0 {
						continue
					}
				}
				if hi != "" {
					c := compareVersions(fp.Version, hi)
					if m.VersionEndExcluding != "" && c >= 0 {
						continue
					}
					if c > 0 {
						continue
					}
				}
				return true
			}
		}
	}
	return false
}

// nvdAllow enforces the unauthenticated NVD budget locally (rolling window).
// Non-blocking: when the budget is spent the fallback is simply skipped —
// offline candidates (if any) are unaffected.
func (c *cveEnricher) nvdAllow() bool {
	c.nvdMu.Lock()
	defer c.nvdMu.Unlock()
	now := time.Now()
	kept := c.nvdTimes[:0]
	for _, t := range c.nvdTimes {
		if now.Sub(t) < nvdWindow {
			kept = append(kept, t)
		}
	}
	c.nvdTimes = kept
	if len(c.nvdTimes) >= nvdBurst {
		return false
	}
	c.nvdTimes = append(c.nvdTimes, now)
	return true
}

func (c *cveEnricher) get(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artex-enrich/1.0")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

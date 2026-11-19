// Strict-scope enforcement (opt-in, our deployment contract): when
// ARTEX_STRICT_SCOPE=1, every network target a tool call tries to reach must
// fall inside the task's scope — company_scope rules of the task's companies
// plus task_scope rows — or inside the box's own infrastructure (loopback and
// private nets, which carry the LM tunnel and the docker bridge). Anything else
// is denied BEFORE user intercept rules run, so a user allow-rule can never
// widen the scope. Off by default for upstream compatibility.
//
// v1 honestly catches literals only: URL hosts (scheme://host), IPv4/IPv6
// literals, and bare host(:port) tokens. It does NOT parse shell syntax —
// targets hidden behind variables, $(...) or base64 payloads are not caught
// (and, just as important, not falsely denied). Write/Edit/MultiEdit and
// web_search carry no direct network egress and are not checked; a call with no
// extractable target passes (reading a local file is not scope's subject).
package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// envStrictScope gates strict-scope enforcement. Read per call (never cached) so
// the flag flips without recreating guards; "1" = on, same ARTEX_* convention as
// ARTEX_ENABLE_SELFUPDATE.
const envStrictScope = "ARTEX_STRICT_SCOPE"

func strictScopeEnabled() bool { return os.Getenv(envStrictScope) == "1" }

// 사용자에게 노출되는 strict-scope 차단 사유(한국어, err* 관례). 이 문자열은
// systemBlockMessage 로 감싸져 에이전트 tool_result 와 /api/audit 감사 로그로
// 함께 흘러간다(ask 차단 경로와 동일한 이중 노출, F16 동형).
const (
	errStrictScopeDeniedFmt = "작업 스코프를 벗어난 대상입니다: %s (스코프 허용 규칙에 이 대상이 없습니다)"
	errStrictScopeLoadFmt   = "작업 스코프를 조회할 수 없어 안전하게 차단합니다(fail-closed): %v"
)

// scopeTarget is one network target extracted from a tool input.
type scopeTarget struct {
	host string // lowercased, no trailing dot
	isIP bool
}

var (
	// scheme://… literal, cut at whitespace/quotes/shell metacharacters so a
	// piped command like `curl http://a|nc b 1` yields host "a", not "a|nc".
	reURL = regexp.MustCompile("(?i)\\b[a-z][a-z0-9+.-]*://[^\\s\"'`<>\\\\|]+")
	// dotted-quad IPv4 candidates; net.ParseIP below rejects 1.2.3.999 etc.
	reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// IPv6-shaped runs (hex digits, colons, dots for v4-mapped forms); validated
	// by net.ParseIP, so MAC addresses and 12:34:56 timestamps fall through.
	reIPv6Run = regexp.MustCompile(`[0-9A-Fa-f:.]{2,45}`)
	// candidate host[:port]/[v6]:port tokens; everything else is a separator.
	reHostTok = regexp.MustCompile(`[A-Za-z0-9.:\-\[\]]+`)
)

// commonFileExts filters dotted tokens that are far likelier local file names
// (loot.tar.gz, report.pdf) than hostnames. A scheme URL still reaches such a
// host (http://x.md is extracted by reURL, not by the bare-token pass).
var commonFileExts = map[string]bool{
	"7z": true, "bak": true, "bin": true, "bz2": true, "conf": true, "crt": true,
	"csv": true, "dat": true, "db": true, "exe": true, "gif": true, "gz": true,
	"html": true, "htm": true, "ico": true, "ini": true, "jpeg": true, "jpg": true,
	"js": true, "json": true, "key": true, "log": true, "md": true, "mp4": true,
	"pdf": true, "pem": true, "png": true, "py": true, "rar": true, "sql": true,
	"svg": true, "tar": true, "txt": true, "xz": true, "yaml": true, "yml": true,
	"zip": true,
}

// commonTLDs gates the bare host(:port) pass (pass 4 only): a dotted token is
// treated as a bare hostname when its last label is a real or internal-use
// TLD. Word chains ending in "ciphers"/"aes" (python module paths) fall out.
// This trades rare false negatives (bare hosts with exotic gTLDs must then use
// a scheme URL to be caught) for no false denies — v1's stated priority.
var commonTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "edu": true, "gov": true,
	"mil": true, "int": true, "io": true, "ai": true, "co": true,
	"kr": true, "jp": true, "cn": true, "tw": true, "hk": true,
	"sg": true, "in": true, "id": true, "my": true, "th": true,
	"vn": true, "au": true, "nz": true, "ru": true, "su": true,
	"by": true, "ua": true, "kz": true, "tr": true, "il": true,
	"ae": true, "sa": true, "eg": true, "za": true, "ke": true,
	"br": true, "mx": true, "ar": true, "cl": true, "pe": true,
	"ca": true, "us": true, "uk": true, "de": true, "fr": true,
	"es": true, "it": true, "nl": true, "be": true, "at": true,
	"ch": true, "se": true, "no": true, "dk": true, "fi": true,
	"is": true, "ie": true, "pt": true, "gr": true, "pl": true,
	"cz": true, "sk": true, "hu": true, "ro": true, "bg": true,
	"rs": true, "hr": true, "si": true, "ee": true, "lv": true,
	"lt": true, "info": true, "biz": true, "xyz": true, "me": true,
	"tv": true, "cc": true, "sh": true, "gg": true, "to": true,
	"dev": true, "app": true, "cloud": true, "pro": true, "name": true,
	"asia": true, "museum": true, "onion": true,
	// reserved for docs/tests and private naming — still hostname-shaped
	"example": true, "test": true, "invalid": true,
	"local": true, "internal": true, "lan": true, "corp": true,
	"home": true, "arpa": true,
}

// extractScopeTargets returns the distinct network targets found in a shell
// command / free-form tool input. Targets hidden behind shell indirection are
// intentionally out of scope for v1 (see the package comment).
func extractScopeTargets(s string) []scopeTarget {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []scopeTarget
	addHost := func(host string) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || seen[host] {
			return
		}
		if net.ParseIP(host) != nil {
			seen[host] = true
			out = append(out, scopeTarget{host: host, isIP: true})
			return
		}
		// Single-label names (localhost, docker service names) cannot be matched
		// against registrable-domain scope rules — v1 treats them as not
		// scope-checkable literals. "localhost" stays always-allowed in the
		// verdict below.
		if !strings.Contains(host, ".") || !validHostnameLabels(host) {
			return
		}
		seen[host] = true
		out = append(out, scopeTarget{host: host, isIP: false})
	}

	// 1) URL hosts — the most reliable signal (scheme prefix disambiguates).
	for _, m := range reURL.FindAllString(s, -1) {
		if u, err := url.Parse(m); err == nil {
			addHost(u.Hostname())
		}
	}
	// 2) Bare IPv4 literals (`nc 10.0.0.5 22`).
	for _, m := range reIPv4.FindAllString(s, -1) {
		addHost(m)
	}
	// 3) Bare IPv6 literals (`ping 2001:db8::1`), including [v6]:port forms.
	// All-colon runs ("::", the SQL cast operator inet_server_addr()::text) have
	// no hex digits and are not addresses — skip them (bench 2026-10-24 FP).
	for _, m := range reIPv6Run.FindAllString(s, -1) {
		if strings.Count(m, ":") >= 2 && strings.Trim(m, ":") != "" {
			addHost(m)
		}
	}
	// 4) Bare host(:port) tokens (`nc host.example.com 443`, `api.acme.co.kr:443`).
	for _, seg := range reHostTok.FindAllString(s, -1) {
		seg = strings.Trim(seg, "-")
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "[") {
			if host, _, err := net.SplitHostPort(seg); err == nil {
				addHost(host)
			} else if host := strings.Trim(seg, "[]"); host != seg {
				addHost(host)
			}
			continue
		}
		host, hadPort := seg, false
		if strings.Count(seg, ":") == 1 {
			if h, _, err := net.SplitHostPort(seg); err == nil && h != "" {
				host, hadPort = h, true
			}
		}
		if strings.Contains(host, ":") {
			continue // IPv6-ish, already handled by pass 3
		}
		host = strings.Trim(host, ".")
		if net.ParseIP(host) != nil {
			addHost(host)
			continue
		}
		if !validHostnameLabels(host) {
			continue
		}
		labels := strings.Split(host, ".")
		if commonFileExts[labels[len(labels)-1]] {
			continue
		}
		// Bare multi-label tokens must end in a known-TLD-shaped label: dotted
		// python module paths (cryptography.hazmat.primitives.ciphers) and other
		// word chains parse as perfectly valid hostnames and were falsely denied
		// (bench 2026-10-24). URL-pass hosts (reURL) keep the full check — a
		// scheme prefix is a strong host signal, a bare word chain is not.
		if !commonTLDs[labels[len(labels)-1]] {
			continue
		}
		// Without a port, require ≥3 labels: catches host.example.com /
		// app.acme.co.kr while skipping 2-label file names (notes.md) — the price
		// is that a bare 2-label host (`ping acme.com`) needs a scheme to count.
		if !hadPort && len(labels) < 3 {
			continue
		}
		addHost(host)
	}
	return out
}

// validHostnameLabels reports whether host is a dotted hostname with RFC-1123
// shaped labels and an alphabetic TLD (≥2 chars) — the shape of a real domain,
// as opposed to "1.2.3.999" or "a..b".
func validHostnameLabels(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, r := range l {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
		if !isAlnumByte(l[0]) || !isAlnumByte(l[len(l)-1]) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func isAlnumByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ScopeAllowList is a task's resolved network allow-list: ip/cidr nets plus
// domains (company_scope domain rules and task_scope root_domain/subdomain
// rows, all lowercased, no trailing dot).
type ScopeAllowList struct {
	Nets    []*net.IPNet
	Domains []string
	// Infra holds infrastructure hostnames the box itself needs (LLM relay,
	// tunnel/callback providers, OSINT feeds). They never count as targets.
	Infra []string
}

// alwaysAllowedNets are unconditionally permitted: the box's own infrastructure
// (LM tunnel on loopback, docker bridge 172.16/12, RFC1918, link-local for cloud
// metadata, IPv6 ULA/link-local). Without them strict scope would strangle the
// agent's own tooling on day one.
var alwaysAllowedNets = mustParseNets(
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fe80::/10", "fc00::/7",
	"0.0.0.0/8",
)

func mustParseNets(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("strict-scope: bad builtin net " + c)
		}
		out = append(out, n)
	}
	return out
}

// checkScopeTargets reports whether every target is allowed; on the first
// violation it returns the offending host ("" when all allowed). Rules: IPs must
// sit in an allowed net (builtin infra nets included); domains must equal or be
// a subdomain of an allowed domain; "localhost" is always allowed.
func checkScopeTargets(targets []scopeTarget, list *ScopeAllowList) (ok bool, denied string) {
	for _, t := range targets {
		if t.isIP {
			ip := net.ParseIP(t.host)
			if ip == nil {
				continue
			}
			if ipInNets(ip, alwaysAllowedNets) || ipInNets(ip, list.Nets) {
				continue
			}
			return false, t.host
		}
		if t.host == "localhost" {
			continue
		}
		if matchAllowedDomain(list.Domains, t.host) || matchAllowedDomain(list.Infra, t.host) {
			continue
		}
		return false, t.host
	}
	return true, ""
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func matchAllowedDomain(domains []string, host string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ScopeSource resolves a task's allow-list. NewDBScopeSource is the pg-backed
// implementation; tests inject fakes.
type ScopeSource interface {
	TaskScope(taskID int64) (*ScopeAllowList, error)
}

// SetScopeSource installs the allow-list source for strict-scope enforcement.
// Call before attaching the hooks to a session (guards are wired once at
// creation; the source is read on every gated call while ARTEX_STRICT_SCOPE=1).
func (g *Guard) SetScopeSource(src ScopeSource) { g.scopeSrc = src }

// scopeInputText returns the network-relevant text of a tool input ("" = not a
// network-touching tool; those are not scope's subject in v1).
func scopeInputText(tool string, input json.RawMessage) string {
	var in struct {
		Command string `json:"command"`
		Text    string `json:"text"`
		URL     string `json:"url"`
	}
	_ = json.Unmarshal(input, &in)
	switch tool {
	case "Bash", "shell_open":
		return in.Command
	case "shell_send":
		return in.Text
	case "WebFetch":
		return in.URL
	}
	return ""
}

// applyStrictScope denies tool calls whose network targets fall outside the
// task's scope. Runs before applyIntercept on purpose: platform scope must not
// be widen-able by a user allow-rule. Not blocked when the feature is off, no
// source is wired, no task context exists (chat/planner), or the input carries
// no extractable target. Fail-closed: an allow-list load error denies — same
// contract as the judge fail-action default.
func (g *Guard) applyStrictScope(ctx context.Context, ev hook.Event, cmd string) (hook.Result, bool) {
	if !strictScopeEnabled() || g.scopeSrc == nil {
		return hook.Result{}, false
	}
	taskID, err := strconv.ParseInt(intercept.TaskIDFromContext(ctx), 10, 64)
	if err != nil || taskID <= 0 {
		return hook.Result{}, false
	}
	text := scopeInputText(ev.ToolName, ev.Input)
	if text == "" {
		return hook.Result{}, false
	}
	targets := extractScopeTargets(text)
	if len(targets) == 0 {
		return hook.Result{}, false
	}
	list, err := g.scopeSrc.TaskScope(taskID)
	if err != nil {
		reason := fmt.Sprintf(errStrictScopeLoadFmt, err)
		g.logScopeDecision(ctx, ev, reason)
		return g.block(ev.ToolName, systemBlockMessage(reason), cmd), true
	}
	if ok, denied := checkScopeTargets(targets, list); !ok {
		reason := fmt.Sprintf(errStrictScopeDeniedFmt, denied)
		g.logScopeDecision(ctx, ev, reason)
		return g.block(ev.ToolName, systemBlockMessage(reason), cmd), true
	}
	return hook.Result{}, false
}

// logScopeDecision mirrors a scope denial into the intercept history (status
// "denied", RuleID 0 — the decision comes from platform scope, not a rule), so
// out-of-scope blocks are visible on the same review pages as rule denials.
func (g *Guard) logScopeDecision(ctx context.Context, ev hook.Event, reason string) {
	if g.interceptor == nil {
		return
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx),
		intercept.Decision{Action: "deny", Message: reason}, ev.ToolName, ev.Input, "denied")
}

// --- pg-backed allow-list source ---

// scopeCacheTTL bounds how stale a cached allow-list may be; scope edits land
// within this window without any invalidation plumbing.
const scopeCacheTTL = 30 * time.Second

// dbScopeSource loads allow-lists from task_scope + company_scope, cached per
// task so the per-tool-call cost is one map hit instead of 1+N SQL queries.
type dbScopeSource struct {
	pg    *db.DB
	mu    sync.Mutex
	cache map[int64]scopeCacheEntry
}

type scopeCacheEntry struct {
	list    *ScopeAllowList
	expires time.Time
}

// NewDBScopeSource returns a ScopeSource backed by pg. Safe for concurrent use.
func NewDBScopeSource(pg *db.DB) ScopeSource {
	return &dbScopeSource{pg: pg, cache: map[int64]scopeCacheEntry{}}
}

func (s *dbScopeSource) TaskScope(taskID int64) (*ScopeAllowList, error) {
	s.mu.Lock()
	if e, ok := s.cache[taskID]; ok && time.Now().Before(e.expires) {
		s.mu.Unlock()
		return e.list, nil
	}
	s.mu.Unlock()

	list, err := s.load(taskID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[taskID] = scopeCacheEntry{list: list, expires: time.Now().Add(scopeCacheTTL)}
	s.mu.Unlock()
	return list, nil
}

// load merges task_scope rows (root_domain/subdomain/ip/cidr) and, for every
// company row, that company's company_scope rules (domain + ip/cidr). icp and
// keyword rows carry no network target and are ignored here. Unparseable nets
// are skipped rather than failing the whole call — a scope row that never
// parses authorizes nothing either way, and the verdict stays conservative.
func (s *dbScopeSource) load(taskID int64) (*ScopeAllowList, error) {
	rows, err := s.pg.Assets().ListTaskScope(taskID)
	if err != nil {
		return nil, err
	}
	list := &ScopeAllowList{}
	addNet := func(cidr string) {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && n != nil {
			list.Nets = append(list.Nets, n)
		}
	}
	addDomain := func(d string) {
		if d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), ".")); d != "" {
			list.Domains = append(list.Domains, d)
		}
	}
	for _, ts := range rows {
		switch ts.Kind {
		case "root_domain", "subdomain":
			addDomain(ts.Domain)
		case "ip", "cidr", "asn":
			addNet(ts.Net)
		case "infra":
			addDomain(ts.Domain)
			list.Infra = append(list.Infra, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ts.Domain), ".")))
		case "company":
			if ts.CompanyID == nil || *ts.CompanyID <= 0 {
				continue
			}
			rules, err := s.pg.Companies().GetScope(*ts.CompanyID)
			if err != nil {
				return nil, err
			}
			for _, r := range rules {
				switch r.Kind {
				case "domain":
					addDomain(r.Domain)
				case "ip", "cidr":
					addNet(r.Net)
				}
			}
		}
	}
	return list, nil
}

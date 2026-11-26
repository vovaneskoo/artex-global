package enrich

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fpOf(t *testing.T, in string) []fingerprint {
	t.Helper()
	return parseFingerprints(in)
}

func TestParseFingerprints(t *testing.T) {
	cases := []struct {
		in   string
		want []fingerprint
	}{
		{"Server: nginx/1.18.0", []fingerprint{{"nginx", "1.18.0"}}},
		{"X-Powered-By: PHP/7.4.33", []fingerprint{{"php", "7.4.33"}}},
		{"Nginx[1.18.0],jQuery 3.5.1", []fingerprint{{"nginx", "1.18.0"}, {"jquery", "3.5.1"}}},
		{"Apache/2.4.49 (Unix)", []fingerprint{{"apache", "2.4.49"}}},
		{"Microsoft-IIS/10.0", []fingerprint{{"microsoft iis", "10.0"}}},
		{"Apache Tomcat 9.0.31", []fingerprint{{"apache tomcat", "9.0.31"}}},
		// noise must not fire
		{"error 404 page not found", nil},
		{"redirect to port 8080", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := fpOf(t, c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseFingerprints(%q): got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseFingerprints(%q)[%d]: got %+v, want %+v", c.in, i, got[i], c.want[i])
			}
		}
	}
}

const edbFixture = `id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags
50383,exploits/linux/webapps/50383.py,"nginx 1.18.0 - Path Traversal and Remote Code Execution",2021-06-01,author,webapps,linux,,2021-06-01,2023-05-10,1,CVE-2021-23017
41976,exploits/linux/dos/41976.py,"Nginx 1.18.0 - Resolver Off-by-One (Denial of Service)",2021-05-31,author,dos,linux,,2021-05-31,2021-05-31,1,CVE-2021-23018
48660,exploits/linux/webapps/48660.py,"Nginx 1.9.14 - 1.20.0 - Resolver Off-by-One",2021-05-26,author,webapps,linux,,2021-05-26,2022-06-01,1,CVE-2021-23017
51131,exploits/linux/webapps/51131.py,"nginx 1.21.0 - Some Other Bug",2022-01-01,author,webapps,linux,,2022-01-01,2022-01-01,0,
49866,exploits/linux/webapps/49866.py,"Apache 2.4.49 - Path Traversal & RCE",2021-10-07,author,webapps,linux,,2021-10-07,2024-02-02,1,CVE-2021-41773;CVE-2021-42013
34666,exploits/windows/remote/34666.pl,"Microsoft IIS 10.0 WebDAV - Remote Code Execution",2017-03-27,author,remote,windows,80,2017-03-27,2019-01-01,1,CVE-2017-7269
46988,exploits/linux/webapps/46988.py,"Nginx before 1.20.1 - Missing Header Check",2021-09-01,author,webapps,linux,,2021-09-01,2021-09-01,0,CVE-2021-99999
`

func fixtureEnricher(t *testing.T) *cveEnricher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "files_exploits.csv")
	if err := os.WriteFile(path, []byte(edbFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return &cveEnricher{
		enabled: true,
		online:  false,
		edbPath: path,
		client:  &http.Client{},
	}
}

func TestLocalEDBMatching(t *testing.T) {
	c := fixtureEnricher(t)

	// exact token hit + range hit, dos row excluded
	got := c.localEDB(fingerprint{"nginx", "1.18.0"})
	if len(got) != 3 { // 50383 exact, 48660 range 1.9.14-1.20.0, 46988 before 1.20.1
		t.Fatalf("nginx 1.18.0: want 3 candidates (exact+2 ranges, dos excluded), got %d: %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, g := range got {
		ids[g.EDB] = true
	}
	if !ids["50383"] || !ids["48660"] || !ids["46988"] {
		t.Errorf("expected EDB 50383+48660+46988, got %+v", got)
	}

	// outside every range and no exact token: no hit
	if got := c.localEDB(fingerprint{"nginx", "1.21.5"}); len(got) != 0 {
		t.Errorf("nginx 1.21.5 unexpected hits: %+v", got)
	}

	// exact-only hit for a different version
	got = c.localEDB(fingerprint{"nginx", "1.21.0"})
	if len(got) != 1 || got[0].EDB != "51131" {
		t.Errorf("nginx 1.21.0: want only EDB 51131, got %+v", got)
	}

	// multi-word product normalized from hyphenated header token
	got = c.localEDB(fingerprint{"microsoft iis", "10.0"})
	if len(got) != 1 || got[0].EDB != "34666" {
		t.Errorf("microsoft iis 10.0: want EDB 34666, got %+v", got)
	}

	// no product word match: php must not hit phpmyadmin wording
	if got := c.localEDB(fingerprint{"php", "2.4.49"}); len(got) != 0 {
		t.Errorf("php should not match apache rows, got %+v", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.18", "1.18.0", 0},
		{"1.4", "1.14", -1},
		{"1.20.0", "1.9.14", 1},
		{"2.0", "2.0.1", -1},
		{"1.18.0", "1.18.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionRanges(t *testing.T) {
	// bounded pair: strict containment
	rs := versionRanges("nginx 1.3.9 < 1.4.0 something")
	if len(rs) != 1 || rs[0] != [2]string{"1.3.9", "1.4.0"} {
		t.Fatalf("pair: got %+v", rs)
	}
	row := edbRow{ranges: rs}
	for _, v := range []string{"1.3.9", "1.3.55", "1.4.0"} {
		if !row.containsVersion(v) {
			t.Errorf("version %s should be inside %+v", v, rs)
		}
	}
	for _, v := range []string{"1.3.8", "1.4.1"} {
		if row.containsVersion(v) {
			t.Errorf("version %s must be outside %+v", v, rs)
		}
	}

	// "before X" / "< X": open-start range [0, X] — 1.18.0 < 1.20.1 is a hit
	rs = versionRanges("nginx before 1.20.1 - missing header check")
	if len(rs) == 0 || rs[0][1] != "1.20.1" {
		t.Fatalf("before: got %+v", rs)
	}
	row = edbRow{ranges: rs}
	if !row.containsVersion("1.18.0") || row.containsVersion("1.20.2") {
		t.Errorf("before-range containment wrong: %+v", rs)
	}

	// hyphen pair with spaces
	rs = versionRanges("nginx 1.9.14 - 1.20.0 - resolver off-by-one")
	if len(rs) == 0 || rs[0] != [2]string{"1.9.14", "1.20.0"} {
		t.Fatalf("hyphen pair: got %+v", rs)
	}
}

func TestResearchOnlineFeeds(t *testing.T) {
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-41773"}]}`))
	}))
	defer kev.Close()
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") != "CVE-2021-41773" {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		w.Write([]byte(`{"data":[{"cve":"CVE-2021-41773","epss":"0.96421","percentile":"0.9"}]}`))
	}))
	defer epss.Close()
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kw := r.URL.Query().Get("keywordSearch"); kw != "gitlab" {
			w.Write([]byte(`{"vulnerabilities":[],"totalResults":0}`))
			return
		}
		// criteria mirror the real NVD shape: vendor tokens (gitlab under gitlab),
		// version bounds, and one lookalike product that must be rejected
		w.Write([]byte(`{"totalResults":3,"startIndex":0,"vulnerabilities":[
			{"cve":{"id":"CVE-2024-0402","descriptions":[{"lang":"en","value":"GitLab account takeover"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL"}}]},
			  "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*","versionStartIncluding":"16.5.0","versionEndExcluding":"16.8.1"}]}]}]}},
			{"cve":{"id":"CVE-2020-99998","descriptions":[{"lang":"en","value":"older gitlab XSS"}],
			  "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*","versionEndExcluding":"13.1.0"}]}]}]}},
			{"cve":{"id":"CVE-2020-99999","descriptions":[{"lang":"en","value":"gitlab-backup unrelated product RCE"}],
			  "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:someone:gitlab_backup:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.0","versionEndExcluding":"9.9.9"}]}]}]}}
		]}`))
	}))
	defer nvd.Close()

	c := fixtureEnricher(t)
	c.online = true
	c.kev, c.epss, c.nvd = kev.URL, epss.URL, nvd.URL

	// local hit + KEV/EPSS tagging
	got := c.research("Apache 2.4.49")
	if len(got) == 0 {
		t.Fatal("apache 2.4.49: no candidates")
	}
	if !got[0].KEV {
		t.Errorf("CVE-2021-41773 must be KEV-tagged: %+v", got[0])
	}
	if got[0].EPSS < 0.9 {
		t.Errorf("EPSS must be attached, got %+v", got[0])
	}

	// no local hit → NVD product query + CPE range filter:
	// 16.8.0 is inside CVE-2024-0402 (< 16.8.1), outside the 13.1.0-bound one,
	// and the gitlab_backup lookalike must be rejected by product equality
	got = c.research("Gitlab 16.8.0")
	if len(got) != 1 || got[0].CVE != "CVE-2024-0402" || got[0].Source != "nvd" {
		t.Fatalf("gitlab fallback: got %+v", got)
	}
	if got[0].Title == "" {
		t.Errorf("nvd candidate must carry the advisory title")
	}
	if got[0].Type != "cvss:CRITICAL" {
		t.Errorf("severity not carried: %+v", got[0])
	}

	// versionless input is a no-op
	if got := c.research("Nginx, Vue, Cloudflare"); got != nil {
		t.Errorf("versionless fingerprint must yield nothing, got %+v", got)
	}
}

func TestNVDBudget(t *testing.T) {
	c := fixtureEnricher(t)
	for i := 0; i < nvdBurst; i++ {
		if !c.nvdAllow() {
			t.Fatalf("call %d within burst must be allowed", i)
		}
	}
	if c.nvdAllow() {
		t.Fatal("budget must be exhausted after burst")
	}
}

func TestDisabledEnricher(t *testing.T) {
	c := fixtureEnricher(t)
	c.enabled = false
	if got := c.research("nginx 1.18.0"); got != nil {
		t.Errorf("disabled enricher must yield nothing, got %+v", got)
	}
}

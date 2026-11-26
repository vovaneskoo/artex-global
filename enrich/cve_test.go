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

const edbFixture = `id,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags
50383,"nginx 1.18.0 - Path Traversal and Remote Code Execution",2021-06-01,author,webapps,linux,,2021-06-01,2023-05-10,1,CVE-2021-23017
41976,"Nginx 1.18.0 - Resolver Off-by-One (Denial of Service)",2021-05-31,author,dos,linux,,2021-05-31,2021-05-31,1,CVE-2021-23018
51131,"nginx 1.21.0 - Some Other Bug",2022-01-01,author,webapps,linux,,2022-01-01,2022-01-01,0,
49866,"Apache 2.4.49 - Path Traversal & RCE",2021-10-07,author,webapps,linux,,2021-10-07,2024-02-02,1,CVE-2021-41773;CVE-2021-42013
34666,"Microsoft IIS 10.0 WebDAV - Remote Code Execution",2017-03-27,author,remote,windows,80,2017-03-27,2019-01-01,1,CVE-2017-7269
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

	// exact version hit, dos row excluded, CVE code attached
	got := c.localEDB(fingerprint{"nginx", "1.18.0"})
	if len(got) != 1 {
		t.Fatalf("nginx 1.18.0: want 1 candidate (dos excluded), got %d: %+v", len(got), got)
	}
	if got[0].EDB != "50383" || got[0].CVE != "CVE-2021-23017" || !got[0].Verified {
		t.Errorf("nginx candidate wrong: %+v", got[0])
	}

	// version boundary: 1.18 must NOT match 1.18.0
	if got := c.localEDB(fingerprint{"nginx", "1.18"}); len(got) != 0 {
		t.Errorf("nginx 1.18 should not match 1.18.0 rows, got %+v", got)
	}

	// wrong version of the right product: no hit
	if got := c.localEDB(fingerprint{"nginx", "1.21.1"}); len(got) != 0 {
		t.Errorf("nginx 1.21.1 unexpected hits: %+v", got)
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
		if kw := r.URL.Query().Get("keywordSearch"); kw != "struts 2.3.31" {
			w.Write([]byte(`{"vulnerabilities":[],"totalResults":0}`))
			return
		}
		w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2017-5638","descriptions":[{"lang":"en","value":"Apache Struts 2.3.31 FileUpload RCE"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL"}}]}}}]}`))
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

	// no local hit → NVD keyword fallback
	got = c.research("Struts 2.3.31")
	if len(got) != 1 || got[0].CVE != "CVE-2017-5638" || got[0].Source != "nvd" {
		t.Fatalf("struts fallback: got %+v", got)
	}
	if got[0].Title == "" {
		t.Errorf("nvd candidate must carry the advisory title")
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

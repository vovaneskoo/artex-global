package agent

import (
	"strings"
	"sync"
	"testing"
)

// fakeEnrich records enrichment triggers fired by insert_assets.
type fakeEnrich struct {
	mu        sync.Mutex
	resolved  []string
	probed    []string
	researched []string
}

func (f *fakeEnrich) ResolveDomain(id int64, host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, host)
}

func (f *fakeEnrich) ProbeSite(id int64, url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probed = append(f.probed, url)
}

func (f *fakeEnrich) ResearchCVE(id int64, fingerprint string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.researched = append(f.researched, fingerprint)
}

// TestInsertAssetsEnrichTriggers verifies the enrichment triggers fire per
// asset type: domains → DNS, http service → probe + CVE research when the
// technologies carry a version. The enrich layer used to be wired but never
// triggered — this is the regression lock for that.
func TestInsertAssetsEnrichTriggers(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	fake := &fakeEnrich{}
	ts := NewToolSet(nil, "")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetEnrich(fake)
	defer d.Exec(`DELETE FROM assets WHERE url='https://enrich-trigger.example.com' OR domain IN ('enrich-trigger.example.com','example.com')`)

	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{
				"type":         "subdomain",
				"domain":       "enrich-trigger.example.com",
			},
			map[string]any{
				"type":         "service",
				"url":          "https://enrich-trigger.example.com",
				"technologies": []string{"Nginx 1.18.0", "Vue", "Cloudflare"},
			},
		},
	})
	if errs, _ := out["errors"].([]any); len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.resolved) != 1 || fake.resolved[0] != "enrich-trigger.example.com" {
		t.Errorf("ResolveDomain: got %v", fake.resolved)
	}
	if len(fake.probed) != 1 || fake.probed[0] != "https://enrich-trigger.example.com" {
		t.Errorf("ProbeSite: got %v", fake.probed)
	}
	if len(fake.researched) != 1 || !strings.Contains(fake.researched[0], "Nginx 1.18.0") {
		t.Errorf("ResearchCVE: got %v (versioned technologies only)", fake.researched)
	}
}

// TestVersionedTechnologies: only digit-bearing entries survive the filter.
func TestVersionedTechnologies(t *testing.T) {
	got := versionedTechnologies([]string{"Nginx", "PHP/7.4.33", "Apache Tomcat 9.0.31", "Cloudflare"})
	if got != "PHP/7.4.33; Apache Tomcat 9.0.31" {
		t.Errorf("got %q", got)
	}
	if versionedTechnologies([]string{"Nginx", "Vue"}) != "" {
		t.Errorf("versionless list must yield empty string")
	}
}

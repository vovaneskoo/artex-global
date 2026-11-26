package db

import (
	"encoding/json"
	"testing"
)

// TestMergeExtra verifies the shallow JSONB merge used by the enrich engine's
// async write-back: patch keys replace, unrelated extra keys survive.
func TestMergeExtra(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const url = "https://merge-extra-test.example.com"
	defer d.Exec(`DELETE FROM assets WHERE url=$1`, url)

	id, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: url, TaskID: 0})
	if err != nil || id <= 0 {
		t.Fatalf("upsert: id=%d err=%v", id, err)
	}

	// first write: headers
	if err := d.Assets().MergeExtra(id, map[string]any{
		"http_headers": map[string]string{"Server": "nginx/1.18.0"},
	}); err != nil {
		t.Fatal(err)
	}
	// second write: cve candidates — must not wipe http_headers
	if err := d.Assets().MergeExtra(id, map[string]any{
		"cve": map[string]any{"candidates": []map[string]any{{"cve": "CVE-2021-23017"}}},
	}); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := d.QueryRow(`SELECT extra FROM assets WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var extra map[string]any
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatalf("extra not json: %v (%s)", err, raw)
	}
	if extra["http_headers"] == nil {
		t.Errorf("http_headers wiped by second merge: %s", raw)
	}
	cve, ok := extra["cve"].(map[string]any)
	if !ok {
		t.Fatalf("cve key missing: %s", raw)
	}
	if _, ok := cve["candidates"]; !ok {
		t.Errorf("candidates missing: %s", raw)
	}

	// replacing the same top-level key must replace it wholesale
	if err := d.Assets().MergeExtra(id, map[string]any{
		"cve": map[string]any{"updated": "t2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT extra FROM assets WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatal(err)
	}
	cve, _ = extra["cve"].(map[string]any)
	if cve == nil || cve["candidates"] != nil {
		t.Errorf("cve key must be replaced wholesale, got %s", raw)
	}

	// best-effort semantics: missing asset is not an error
	if err := d.Assets().MergeExtra(1<<40, map[string]any{"x": 1}); err != nil {
		t.Errorf("missing asset must not error, got %v", err)
	}
}

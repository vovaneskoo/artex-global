package server

import "testing"

func TestCVELineDedupesAndCaps(t *testing.T) {
	found := []cveCandidate{
		{cve: "CVE-2015-3306", title: "a"},
		{cve: "CVE-2015-3306", title: "b"},
		{cve: "CVE-2015-3306", title: "c"},
		{cve: "CVE-2021-1"},
		{cve: "CVE-2021-2"},
		{cve: "CVE-2021-3"},
		{cve: "CVE-2021-4"},
		{cve: "CVE-2021-5"},
		{cve: "CVE-2021-6"},
	}
	if got, want := cveListLine(found, 5), "CVE-2015-3306, CVE-2021-1, CVE-2021-2, CVE-2021-3, CVE-2021-4 (+2 more)"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if n := len(distinctCVEs(found)); n != 7 {
		t.Fatalf("distinct = %d, want 7", n)
	}
	if got := cveListLine(nil, 5); got != "" {
		t.Fatalf("empty: %q", got)
	}
	if got := cveListLine([]cveCandidate{{cve: "CVE-1"}, {cve: "CVE-1"}}, 5); got != "CVE-1" {
		t.Fatalf("single dup: %q", got)
	}
}

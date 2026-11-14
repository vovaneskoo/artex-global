package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// factNode builds a KindFact node the way record_fact (agent/tools.go) stores
// it: payload {summary, confidence}, state "confirmed".
func factNode(id int64, summary, confidence string) *db.Node {
	return &db.Node{
		ID: id, Kind: db.KindFact, State: "confirmed",
		Payload: mustJSON(map[string]any{"summary": summary, "confidence": confidence}),
	}
}

// originFactNode mimics the task-root fact seeded at creation (state "origin"):
// its payload restates the task description and must never be listed as an
// observation.
func originFactNode(id int64) *db.Node {
	return &db.Node{
		ID: id, Kind: db.KindFact, State: db.StateOrigin,
		Payload: mustJSON(map[string]any{"summary": "任务起点：demo task；目标：demo goal"}),
	}
}

func fullInput() Input {
	return Input{
		Title:         "Scoped task",
		Goal:          "verify sandbox",
		GeneratedAt:   time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
		TaskID:        "42",
		ExplorationID: 7,
		Status:        "done",
		AssetCounts:   map[string]int{"root_domain": 2, "ip": 3},
		Facts: []*db.Node{
			factNode(11, "port 22 closed on edge host", "observed"),
			factNode(12, "login page likely behind SSO", "inferred"),
			originFactNode(1),
		},
		Findings: []*db.Node{
			{
				ID:    21,
				Kind:  db.KindFinding,
				State: "confirmed",
				Payload: mustJSON(map[string]any{
					"vulnclass": "SQL Injection", "name": "Login SQLi", "severity": "high",
					"summary":  "error-based SQL injection in login",
					"evidence": map[string]string{"poc": "' OR '1'='1 -- secret= hunter2"},
				}),
			},
		},
		FindingRefs: map[int64]FindingRef{21: {FindingID: 123, Status: "confirmed", Traffic: 2}},
	}
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

// TestReportRussianLocale: the ru locale renders a Russian skeleton.
func TestReportRussianLocale(t *testing.T) {
	in := fullInput()
	in.Locale = "ru"
	out := Markdown(in)
	for _, want := range []string{
		"# Отчёт о тестировании на проникновение: Scoped task",
		"- **Цель задачи**: verify sandbox",
		"## Сводка",
		"- Подтверждённых уязвимостей: **1**",
		"- Наблюдаемых фактов: 1",
		"- Непроверенных выводов: 1",
		"## Подтверждённые уязвимости",
		"## Наблюдаемые факты",
		"## Непроверенные выводы",
		"## Воспроизводимость и охват",
		"Отсылка к доказательству: finding #123 · статус confirmed · привязок трафика: 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ru report missing %q:\n%s", want, out)
		}
	}
	if r, ok := containsHan(out); ok {
		t.Errorf("ru report contains Han %q", string(r))
	}
}

// TestReportEnglishLocale: the en locale renders an English skeleton.
func TestReportEnglishLocale(t *testing.T) {
	in := fullInput()
	in.Locale = "en"
	out := Markdown(in)
	for _, want := range []string{
		"# Penetration Test Report: Scoped task",
		"- **Task goal**: verify sandbox",
		"## Summary",
		"- Confirmed findings: **1**",
		"- Observed facts: 1",
		"- Unverified conclusions: 1",
		"## Confirmed vulnerabilities",
		"## Observed facts",
		"## Unverified conclusions",
		"## Reproducibility and scope",
		"Evidence reference: finding #123 · status confirmed · traffic evidence bindings: 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("en report missing %q:\n%s", want, out)
		}
	}
}

// TestReportFallbackLocale: unsupported locales (and the empty locale) fall
// back to the English skeleton — byte-identical to an explicit "en".
func TestReportFallbackLocale(t *testing.T) {
	reference := Markdown(fullInputWithLocale("en"))
	for _, locale := range []string{"", "fr", "EN", "zh", "xx-nonsense"} {
		if got := Markdown(fullInputWithLocale(locale)); got != reference {
			t.Errorf("locale %q did not fall back to the en skeleton:\n--- got ---\n%s\n--- en ---\n%s", locale, got, reference)
		}
	}
}

func fullInputWithLocale(locale string) Input {
	in := fullInput()
	in.Locale = locale
	return in
}

// TestReportSeparatesFactsFindingsUnverified: observed facts, findings and
// inferred conclusions land in their own sections; the seeded origin fact is
// excluded; an inferred fact is labelled unverified.
func TestReportSeparatesFactsFindingsUnverified(t *testing.T) {
	out := Markdown(fullInputWithLocale("en"))

	observed := strings.Index(out, "## Observed facts")
	unverified := strings.Index(out, "## Unverified conclusions")
	repro := strings.Index(out, "## Reproducibility and scope")
	if observed < 0 || unverified < 0 || repro < 0 || !(observed < unverified && unverified < repro) {
		t.Fatalf("sections missing or out of order (observed=%d unverified=%d repro=%d):\n%s", observed, unverified, repro, out)
	}
	observedSection := out[observed:unverified]
	unverifiedSection := out[unverified:repro]

	if !strings.Contains(observedSection, "port 22 closed on edge host") {
		t.Errorf("observed fact missing from Observed facts:\n%s", observedSection)
	}
	if strings.Contains(observedSection, "login page likely behind SSO") {
		t.Errorf("inferred fact leaked into Observed facts:\n%s", observedSection)
	}
	if !strings.Contains(unverifiedSection, "login page likely behind SSO") {
		t.Errorf("inferred fact missing from Unverified conclusions:\n%s", unverifiedSection)
	}
	if !strings.Contains(unverifiedSection, "(inferred — not independently verified)") {
		t.Errorf("unverified note missing:\n%s", unverifiedSection)
	}
	if strings.Contains(out, "任务起点") {
		t.Errorf("origin (task-root) fact rendered as an observation:\n%s", out)
	}
}

// TestReportReferencesEvidenceWithoutRawSecrets: the report references the
// findings row and traffic counts, and never inlines the raw PoC/evidence text
// (which may contain secrets).
func TestReportReferencesEvidenceWithoutRawSecrets(t *testing.T) {
	out := Markdown(fullInputWithLocale("en"))
	if !strings.Contains(out, "finding #123") {
		t.Errorf("evidence reference to the findings row missing:\n%s", out)
	}
	if strings.Contains(out, "' OR '1'='1") {
		t.Errorf("raw PoC inlined into the report:\n%s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("raw secret inlined into the report:\n%s", out)
	}

	// Same finding without a findings-table row: the reference degrades to an
	// explicit "no reference" line instead of pretending evidence exists.
	in := fullInputWithLocale("en")
	in.FindingRefs = nil
	out = Markdown(in)
	if !strings.Contains(out, "Evidence reference: none") {
		t.Errorf("missing-ref line missing:\n%s", out)
	}
}

// TestReportZeroFindingsIsNotProofOfSafety: with no findings the report must
// say what was actually done, not read as an all-clear.
func TestReportZeroFindingsIsNotProofOfSafety(t *testing.T) {
	in := fullInputWithLocale("en")
	in.Findings = nil
	in.FindingRefs = nil
	out := Markdown(in)
	if !strings.Contains(out, "No confirmed vulnerabilities were recorded for this task.") {
		t.Errorf("zero-findings honesty line missing:\n%s", out)
	}
	if !strings.Contains(out, "not proof that the targets are secure") {
		t.Errorf("zero-findings line lacks the not-proof qualifier:\n%s", out)
	}
	if !strings.Contains(out, "- Observed facts: 1") {
		t.Errorf("observed work vanished from the summary of a zero-findings report:\n%s", out)
	}

	ru := fullInputWithLocale("ru")
	ru.Findings = nil
	ru.FindingRefs = nil
	out = Markdown(ru)
	if !strings.Contains(out, "не является доказательством защищённости целей") {
		t.Errorf("ru zero-findings line lacks the not-proof qualifier:\n%s", out)
	}
}

// TestReportInheritedSourcesNote: source tasks are disclosed, so inherited
// results are not silently claimed as this task's own.
func TestReportInheritedSourcesNote(t *testing.T) {
	in := fullInputWithLocale("en")
	in.SourceTaskIDs = []int64{5, 9}
	out := Markdown(in)
	if !strings.Contains(out, "inherited context from task(s) #5, #9") {
		t.Errorf("inherited-source note missing:\n%s", out)
	}
}

// Package report renders a deliverable Markdown report from the exploration
// graph (docs §15 P5). The report is a task deliverable, so it separates three
// kinds of statements — observed facts, confirmed findings, and unverified
// (inferred) conclusions — references evidence by id instead of inlining raw
// captures, and states its scope explicitly. The skeleton is localized:
// "en", "ru" and "ko" are supported; any other locale (including "") falls
// back to English.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// FindingRef is the evidence reference for one finding node: the standalone
// findings-table row (id + triage status) and the number of bound traffic
// evidence snapshots. Raw evidence text is deliberately NOT part of the
// reference — the deliverable points at the findings page / evidence store
// instead of pasting raw captures (and whatever secrets they hold) into a
// Markdown file.
type FindingRef struct {
	FindingID int64
	Status    string
	Traffic   int
}

// Input bundles what the report needs. The caller must supply task-scoped
// data: asset counts for the task's own assets (AssetStore.CountsByTypeForTask),
// nodes from the task's own exploration store, and refs for the task's own
// findings rows (DB.FindingMetaByNodeID). Mixing in other tasks'/projects' data
// is a caller bug the renderer cannot detect — the scope line at the bottom is
// generated from TaskID/ExplorationID so a mismatch is auditable.
type Input struct {
	Title       string
	Goal        string
	GeneratedAt time.Time
	Locale      string // "en" | "ru" | "ko"; anything else (incl. "") → English

	TaskID        string
	ExplorationID int64
	Status        string // lifecycle status as shown in the UI ("" = omit the line)
	CreatedAt     time.Time
	CompletedAt   time.Time // zero = not finished
	SourceTaskIDs []int64   // tasks whose context this one inherited; their findings stay in their own reports

	AssetCounts map[string]int
	Facts       []*db.Node // KindFact nodes; the renderer splits them by confidence
	Findings    []*db.Node // KindFinding nodes (confirmed vulnerabilities)
	FindingRefs map[int64]FindingRef
}

// factConfidence values written by record_fact (agent/tools.go):
// "observed" (directly seen) vs "inferred" (deduced). Facts predate the field,
// so "" is treated as observed — an unqualified fact is still a worker's
// exploration result, and only an explicit "inferred" marks an unverified
// conclusion.
const confidenceInferred = "inferred"

type findingView struct {
	VulnClass string
	Name      string
	Severity  string
	Summary   string
}

// parseFinding extracts the display fields of a finding node. The payload also
// carries evidence.poc (raw evidence text); it is intentionally not parsed —
// the report references evidence by id (FindingRef), never inlines it.
func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Summary   string `json:"summary"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{p.VulnClass, p.Name, p.Severity, p.Summary}
}

func parseFact(n *db.Node) (summary, confidence string) {
	var p struct {
		Summary    string `json:"summary"`
		Confidence string `json:"confidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Summary, strings.ToLower(strings.TrimSpace(p.Confidence))
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// bundleFor resolves the skeleton language. Supported: en, ru, ko. Everything
// else — including the empty locale — falls back to English (the config
// package's DefaultLanguage), so an unknown UI locale still yields a readable,
// deterministic report instead of mixed-language output.
func bundleFor(locale string) bundle {
	switch strings.ToLower(strings.TrimSpace(locale)) {
	case "ru":
		return ruBundle
	case "ko":
		return koBundle
	default:
		return enBundle
	}
}

// Markdown renders the report.
func Markdown(in Input) string {
	L := bundleFor(in.Locale)
	var b strings.Builder

	// observed vs unverified: split facts by confidence, dropping the seeded
	// origin fact (state "origin" holds the task description, not an observation).
	var observed, unverified []*db.Node
	for _, n := range in.Facts {
		if n == nil || n.State == db.StateOrigin {
			continue
		}
		if _, conf := parseFact(n); conf == confidenceInferred {
			unverified = append(unverified, n)
			continue
		}
		observed = append(observed, n)
	}

	fmt.Fprintf(&b, "# %s%s\n\n", L.titlePrefix, nz(in.Title, L.unnamedTask))
	fmt.Fprintf(&b, "- **%s**: %s\n", L.goalLabel, nz(in.Goal, L.goalUnset))
	if in.TaskID != "" || in.ExplorationID > 0 {
		fmt.Fprintf(&b, "- **%s**: %s", L.taskIDLabel, nz(in.TaskID, "—"))
		if in.ExplorationID > 0 {
			fmt.Fprintf(&b, " (%s #%d)", L.explorationLabel, in.ExplorationID)
		}
		b.WriteString("\n")
	}
	if in.Status != "" {
		fmt.Fprintf(&b, "- **%s**: %s\n", L.statusLabel, in.Status)
	}
	if !in.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "- **%s**: %s\n", L.createdLabel, in.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	if !in.CompletedAt.IsZero() {
		fmt.Fprintf(&b, "- **%s**: %s\n", L.completedLabel, in.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(&b, "- **%s**: %s\n\n", L.generatedLabel, in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// summary
	fmt.Fprintf(&b, "## %s\n\n", L.summaryTitle)
	fmt.Fprintf(&b, "- %s\n", fmt.Sprintf(L.confirmedFindingsFmt, len(in.Findings)))
	fmt.Fprintf(&b, "- %s: %d\n", L.observedFacts, len(observed))
	fmt.Fprintf(&b, "- %s: %d\n", L.unverifiedConclusions, len(unverified))
	fmt.Fprintf(&b, "- %s: ", L.taskAssetsPrefix)
	var types []string
	total := 0
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	if len(types) == 0 {
		b.WriteString(L.taskAssetsEmpty)
	} else {
		for i, t := range types {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
			total += in.AssetCounts[t]
		}
	}
	b.WriteString("\n")
	if len(in.SourceTaskIDs) > 0 {
		ids := make([]string, 0, len(in.SourceTaskIDs))
		for _, id := range in.SourceTaskIDs {
			ids = append(ids, fmt.Sprintf("#%d", id))
		}
		fmt.Fprintf(&b, "\n%s\n", fmt.Sprintf(L.inheritedNote, strings.Join(ids, ", ")))
	}
	b.WriteString("\n")

	// findings (confirmed vulnerabilities)
	fmt.Fprintf(&b, "## %s\n\n", L.findingsTitle)
	if len(in.Findings) == 0 {
		fmt.Fprintf(&b, "_%s_\n\n", L.noFindingsHonest)
	} else {
		fs := make([]findingView, 0, len(in.Findings))
		ns := make([]*db.Node, 0, len(in.Findings))
		for _, n := range in.Findings {
			if n == nil {
				continue
			}
			fs = append(fs, parseFinding(n))
			ns = append(ns, n)
		}
		order := make([]int, len(fs))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(i, j int) bool { return sevRank[fs[order[i]].Severity] < sevRank[fs[order[j]].Severity] })
		for row, idx := range order {
			f, n := fs[idx], ns[idx]
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", row+1, strings.ToUpper(nz(f.Severity, "info")), nz(f.Name, nz(f.VulnClass, L.unclassified)))
			if s := strings.TrimSpace(f.Summary); s != "" {
				fmt.Fprintf(&b, "%s\n\n", s)
			}
			if ref, ok := in.FindingRefs[n.ID]; ok && ref.FindingID > 0 {
				fmt.Fprintf(&b, "- %s\n", fmt.Sprintf(L.evidenceRefFmt, ref.FindingID, nz(ref.Status, "pending"), ref.Traffic))
			} else {
				fmt.Fprintf(&b, "- %s\n", L.noEvidenceRef)
			}
			fmt.Fprintf(&b, "- node #%d\n\n", n.ID)
		}
	}

	// observed facts
	fmt.Fprintf(&b, "## %s\n\n", L.factsTitle)
	if len(observed) == 0 {
		fmt.Fprintf(&b, "_%s_\n\n", L.factsEmpty)
	} else {
		for _, n := range observed {
			summary, _ := parseFact(n)
			fmt.Fprintf(&b, "- node #%d — %s\n", n.ID, nz(summary, L.factsEmpty))
		}
		b.WriteString("\n")
	}

	// unverified conclusions
	fmt.Fprintf(&b, "## %s\n\n", L.unverifiedTitle)
	if len(unverified) == 0 {
		fmt.Fprintf(&b, "_%s_\n\n", L.unverifiedEmpty)
	} else {
		for _, n := range unverified {
			summary, _ := parseFact(n)
			fmt.Fprintf(&b, "- node #%d — %s %s\n", n.ID, nz(summary, L.unverifiedEmpty), L.unverifiedNote)
		}
		b.WriteString("\n")
	}

	// reproducibility & scope
	fmt.Fprintf(&b, "## %s\n\n", L.reproTitle)
	if in.TaskID != "" || in.ExplorationID > 0 {
		fmt.Fprintf(&b, "- %s\n", fmt.Sprintf(L.scopeLine, nz(in.TaskID, "—"), in.ExplorationID))
	}
	fmt.Fprintf(&b, "- %s\n", L.evidenceLine)
	return b.String()
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

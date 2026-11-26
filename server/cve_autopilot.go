package server

import (
	"fmt"
	"log"
	"strings"

	"github.com/Autumn-27/artex/db"
)

type cveCandidate struct{ cve, product, version, title string }

func distinctCVEs(found []cveCandidate) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(found))
	for _, c := range found {
		if seen[c.cve] {
			continue
		}
		seen[c.cve] = true
		out = append(out, c.cve)
	}
	return out
}

// cveListLine renders up to max distinct CVEs plus an "(+N more)" tail.
func cveListLine(found []cveCandidate, max int) string {
	cves := distinctCVEs(found)
	n := len(cves)
	if n > max {
		n = max
	}
	line := strings.Join(cves[:n], ", ")
	if len(cves) > max {
		line += fmt.Sprintf(" (+%d more)", len(cves)-max)
	}
	return line
}

// cveAutopilotFor returns the closure wired into workers of the given task:
// when report_finding fires, we look up the finding's assets, check each for
// CVE candidates (written there by the enrich layer), and — if any exist —
// auto-spawn an "exploit-assessment" intent anchored to the finding node.
// The worker loop picks it up on the next claim without any planner round.
func (s *Server) cveAutopilotFor(t *Task) func(assetIDs []int64, findingNodeID int64, summary string) {
	return func(assetIDs []int64, findingNodeID int64, summary string) {
		if len(assetIDs) == 0 || t.Store == nil || s.m == nil {
			return
		}
		assets, err := s.m.Assets().GetByIDs(assetIDs)
		if err != nil {
			log.Printf("[autopilot] asset lookup failed: %v", err)
			return
		}
		// The intent anchors on ASSET ids (exploration_anchors is node→asset);
		// dedupe them and skip when an autopilot intent on these assets is
		// still queued/running — its own report_finding would otherwise re-spawn.
		uniq := make([]int64, 0, len(assets))
		seen := map[int64]bool{}
		for _, a := range assets {
			if !seen[a.ID] {
				seen[a.ID] = true
				uniq = append(uniq, a.ID)
			}
		}
		if active, err := t.Store.CountActiveAutopilotOnAssets(uniq); err != nil {
			log.Printf("[autopilot] dedupe check failed: %v", err)
		} else if active > 0 {
			log.Printf("[autopilot] skip: %d active autopilot intent(s) already anchor these assets", active)
			return
		}
		// Collect CVE candidates from the finding's assets (Extra["cve"]["candidates"]).
		var found []cveCandidate
		for _, a := range assets {
			if a.Extra == nil {
				continue
			}
			cveRaw, ok := a.Extra["cve"]
			if !ok {
				continue
			}
			m, ok := cveRaw.(map[string]any)
			if !ok {
				continue
			}
			candsRaw, ok := m["candidates"]
			if !ok {
				continue
			}
			cands, ok := candsRaw.([]any)
			if !ok {
				continue
			}
			for _, c := range cands {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				cve, _ := cm["cve"].(string)
				if cve == "" {
					continue
				}
				product, _ := cm["product"].(string)
				version, _ := cm["version"].(string)
				title, _ := cm["title"].(string)
				found = append(found, cveCandidate{cve: cve, product: product, version: version, title: title})
			}
		}
		if len(found) == 0 {
			return
		}
		// The summary must be one line per distinct CVE: EDB often carries the
		// same CVE in several exploits, and repeating it reads like noise.
		list := cveListLine(found, 5)
		payload := map[string]any{
			"summary": fmt.Sprintf(
				"Exploit assessment: confirmed finding %q on affected assets. "+
					"CVE candidates present: %s. Check each candidate against the target version "+
					"(exploit-search for known PoCs, exploit-dev to build one if none fits). "+
					"Report findings back with evidence.",
				summary, list,
			),
			"asset_ids": uniq,
		}
		intentID, err := t.Store.AddIntent(payload, 7, uniq, "autopilot")
		if err != nil {
			log.Printf("[autopilot] intent spawn failed: %v", err)
			return
		}
		// Link finding → intent so the exploration graph carries the provenance.
		if err := t.Store.Link(findingNodeID, db.RelDerivedFrom, intentID); err != nil {
			log.Printf("[autopilot] edge link failed: %v", err)
		}
		log.Printf("[autopilot] spawned exploit-assessment intent #%d from finding node #%d (%d candidates, %d distinct CVE: %s)",
			intentID, findingNodeID, len(found), len(distinctCVEs(found)), list)
	}
}

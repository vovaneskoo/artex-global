package server

import (
	"fmt"
	"log"

	"github.com/Autumn-27/artex/db"
)

// cveAutopilotFor returns the closure wired into workers of the given task:
// when report_finding fires, we look up the finding's assets, check each for
// CVE candidates (written there by the enrich layer), and — if any exist —
// auto-spawn an "exploit-assessment" intent anchored to the finding node.
// The worker loop picks it up on the next claim without any planner round.
func (s *Server) cveAutopilotFor(t *Task) func(assetIDs []int64, findingNodeID int64, summary string) {
	return func(assetIDs []int64, findingNodeID int64, summary string) {
		if len(assetIDs) == 0 || t.Store == nil {
			return
		}
		assets, err := s.m.Assets().GetByIDs(assetIDs)
		if err != nil {
			log.Printf("[autopilot] asset lookup failed: %v", err)
			return
		}
		// Collect CVE candidates from the finding's assets (Extra["cve"]["candidates"]).
		type candidate struct{ cve, product, version, title string }
		var found []candidate
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
				found = append(found, candidate{cve: cve, product: product, version: version, title: title})
			}
		}
		if len(found) == 0 {
			return
		}
		// Build the CVE list for the summary (compact, max 5 shown).
		list := ""
		n := len(found)
		if n > 5 {
			n = 5
		}
		for i := 0; i < n; i++ {
			if i > 0 {
				list += ", "
			}
			list += found[i].cve
		}
		if len(found) > 5 {
			list += fmt.Sprintf(" (+%d more)", len(found)-5)
		}
		payload := map[string]any{
			"summary": fmt.Sprintf(
				"Exploit assessment: confirmed finding %q on affected assets. "+
					"CVE candidates present: %s. Check each candidate against the target version "+
					"(exploit-search for known PoCs, exploit-dev to build one if none fits). "+
					"Report findings back with evidence.",
				summary, list,
			),
			"asset_ids": assetIDs,
		}
		intentID, err := t.Store.AddIntent(payload, 7, []int64{findingNodeID}, "autopilot")
		if err != nil {
			log.Printf("[autopilot] intent spawn failed: %v", err)
			return
		}
		// Link finding → intent so the exploration graph carries the provenance.
		if err := t.Store.Link(findingNodeID, db.RelDerivedFrom, intentID); err != nil {
			log.Printf("[autopilot] edge link failed: %v", err)
		}
		log.Printf("[autopilot] spawned exploit-assessment intent #%d from finding node #%d (%d CVE candidates: %s)",
			intentID, findingNodeID, len(found), list)
	}
}

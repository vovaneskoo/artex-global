package agent

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestOverviewSizeLive prints the per-round overview size for a live exploration
// (set ARTEX_LIVE_DSN and ARTEX_LIVE_EXP). Skipped otherwise.
func TestOverviewSizeLive(t *testing.T) {
	dsn, exp := os.Getenv("ARTEX_LIVE_DSN"), os.Getenv("ARTEX_LIVE_EXP")
	if dsn == "" || exp == "" {
		t.Skip("no ARTEX_LIVE_DSN/ARTEX_LIVE_EXP")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var expID int64
	if err := d.QueryRow(`SELECT id FROM explorations WHERE id=$1`, exp).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	tsx := NewToolSet(d.Exploration(expID), "measure")
	data := tsx.graphOverviewData()
	raw, _ := json.Marshal(data)
	t.Logf("overview JSON: %d bytes; findings=%v facts=%v", len(raw), data["findings"], data["facts"])
}

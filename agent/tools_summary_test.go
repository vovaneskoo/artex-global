package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestClipSummary(t *testing.T) {
	if got := clipSummary("short"); got != "short" {
		t.Fatalf("short unchanged: %q", got)
	}
	long := strings.Repeat("a", overviewSummaryChars+50)
	got, _ := clipSummary(long).(string)
	if len([]rune(got)) != overviewSummaryChars+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long not clipped: len=%d", len([]rune(got)))
	}
}

func TestCompactIntentsClipsSummary(t *testing.T) {
	n := &db.Node{ID: 7, State: "open", Payload: []byte(`{"summary":"` + strings.Repeat("x", overviewSummaryChars+10) + `"}`)}
	got := compactIntents([]*db.Node{n}, nil, nil)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if s, _ := got[0]["summary"].(string); !strings.HasSuffix(s, "…") {
		t.Fatalf("summary not clipped: %q", s)
	}
}

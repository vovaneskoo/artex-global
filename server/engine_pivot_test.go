package server

import (
	"testing"
	"time"
)

// TestPivotDecision pins the wall-detector state machine: findings movement
// resets the dry streak, three dry rounds arm the nudge, the interval spaces
// consecutive nudges, and the last nudge carries the conclude-now flag.
func TestPivotDecision(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	st := newPivotState()

	// First observed round seeds the counter, never nudges.
	if nudge, _ := pivotDecision(st, 0, t0); nudge {
		t.Fatal("seed round must not nudge")
	}
	// Two dry rounds: not yet.
	if nudge, _ := pivotDecision(st, 0, t0.Add(5*time.Minute)); nudge {
		t.Fatal("dry=1 must not nudge")
	}
	if nudge, _ := pivotDecision(st, 0, t0.Add(10*time.Minute)); nudge {
		t.Fatal("dry=2 must not nudge")
	}
	// Third dry round: nudge #1 (not final).
	nudge, final := pivotDecision(st, 0, t0.Add(15*time.Minute))
	if !nudge || final {
		t.Fatalf("dry=3 must nudge non-final, got nudge=%v final=%v", nudge, final)
	}
	if st.nudges != 1 {
		t.Fatalf("nudges=%d, want 1", st.nudges)
	}
	// Interval not elapsed: no second nudge even on more dry rounds.
	if nudge, _ := pivotDecision(st, 0, t0.Add(18*time.Minute)); nudge {
		t.Fatal("nudge inside min interval must be suppressed")
	}
	// A new finding resets the dry streak and the next dry rounds start over.
	if nudge, _ := pivotDecision(st, 1, t0.Add(25*time.Minute)); nudge {
		t.Fatal("finding round must not nudge")
	}
	if nudge, _ := pivotDecision(st, 1, t0.Add(30*time.Minute)); nudge {
		t.Fatal("dry=1 after finding must not nudge")
	}
	// Fast-forward: nudges 2 and 3 land once the interval clears; #3 is final.
	now := t0.Add(50 * time.Minute)
	nudged := 0
	final = false
	for i := 0; i < 6 && nudged < 2; i++ {
		var n bool
		n, final = pivotDecision(st, 1, now.Add(time.Duration(i)*pivotMinInterval))
		if n {
			nudged++
		}
	}
	if nudged != 2 || !final {
		t.Fatalf("want nudges 2..3 with final on #3, got nudged=%d final=%v", nudged, final)
	}
	if st.nudges != pivotMaxPerTask {
		t.Fatalf("nudges=%d, want cap %d", st.nudges, pivotMaxPerTask)
	}
	// Cap reached: no more nudges ever.
	if nudge, _ := pivotDecision(st, 1, now.Add(10*time.Hour)); nudge {
		t.Fatal("nudges beyond cap must be suppressed")
	}
}

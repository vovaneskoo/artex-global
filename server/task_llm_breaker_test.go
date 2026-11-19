package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmpool"
)

// TestChainServeProfileSkipsCoolingActive pins the breaker-aware chain pick:
// a closed active is served as-is, and an active whose breaker is open does not
// fall off the chain when no healthy forward member resolves — it keeps the
// active (previous behavior) rather than erroring. The happy "pick next healthy
// member" path needs a live profile provider and is covered by bench E2E.
func TestChainServeProfileSkipsCoolingActive(t *testing.T) {
	reg := llmpool.NewRegistry(nil, nil)
	s := &Server{llmHealth: reg}
	pt := &db.Task{LLMProfileIDs: []int64{11, 22, 33}}

	if got := s.chainServeProfile(pt, 22); got != 22 {
		t.Fatalf("closed active: want 22, got %d", got)
	}

	// Open every member's breaker (3 consecutive transient failures each).
	for _, id := range pt.LLMProfileIDs {
		for i := 0; i < 3; i++ {
			reg.Trip(id, "boom", false)
		}
	}
	if got := s.chainServeProfile(pt, 22); got != 22 {
		t.Fatalf("all cooling: want fallback to active 22, got %d", got)
	}
	if !reg.IsOpen(22) {
		t.Fatal("active should be open after 3 transient trips")
	}
}

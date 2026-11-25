package server

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// llmDeadFixture builds a manager + goal-bearing task on the live test PG
// (skips when PG is unavailable, mirroring the neighboring settle-path tests).
func llmDeadFixture(t *testing.T, title string) (*Manager, *Engine, *Task) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", t)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask(title, "llm-dead fixture goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.Store.ID()) })
	if _, err := task.Store.AddGoal(map[string]any{"text": "llm-dead fixture goal"}, "human"); err != nil {
		t.Fatal(err)
	}
	return m, NewEngine(m), task
}

// insertUsage seeds the always-on llm_usage ledger the detector meters.
func insertLLMDeadUsage(t *testing.T, m *Manager, taskID, status string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := m.pg.InsertLLMUsage(&db.LLMUsage{
			TaskID: taskID, Worker: "worker", Model: "llmdead-fixture", Status: status,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func countActivityKind(t *testing.T, s *db.ExplorationStore, kind string) int {
	t.Helper()
	acts, _, err := s.ActivityList(nil, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range acts {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

// TestLLMDeadSettleWindsDownAllFailingTask — the P0 night-burn repro in
// miniature: every metered call in the window failed, none succeeded, so the
// coordinator settles the task through the ordinary sequence with the llm_dead
// cause instead of letting workers idle-loop until the stagnation window.
// The final planner round cannot resolve a planner in this harness, so the
// context deadline stands in for it; the terminal commit still must land.
func TestLLMDeadSettleWindsDownAllFailingTask(t *testing.T) {
	m, e, task := llmDeadFixture(t, "llm-dead settle")
	insertLLMDeadUsage(t, m, task.ID, "error", 5)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if !e.llmDeadSettle(ctx, task) {
		t.Fatal("expected llmDeadSettle to fire on 5 failing / 0 OK calls")
	}
	if got := m.TaskStatus(task.ID); got != "timeout" {
		t.Fatalf("task status = %q, want timeout", got)
	}
	if n := countActivityKind(t, task.Store, "llm_dead"); n != 1 {
		t.Fatalf("llm_dead activities = %d, want 1", n)
	}
	if n := countActivityKind(t, task.Store, "llm_stall"); n != 1 {
		t.Fatalf("llm_stall activities = %d, want 1 (fires on the way to settle)", n)
	}
	// Idempotence: a settled task must not be re-judged.
	if e.llmDeadSettle(context.Background(), task) {
		t.Fatal("second llmDeadSettle must not fire on a settled task")
	}
}

// TestLLMDeadSettleWarnsOnceBelowThreshold — the early heads-up: two failing
// calls with zero successes warn exactly once per episode, never settle below
// the min-failure threshold, and any successful call re-arms the warning.
func TestLLMDeadSettleWarnsOnceBelowThreshold(t *testing.T) {
	m, e, task := llmDeadFixture(t, "llm-dead stall")
	insertLLMDeadUsage(t, m, task.ID, "error", 2)

	if e.llmDeadSettle(context.Background(), task) {
		t.Fatal("below minFails the detector must warn, not settle")
	}
	if n := countActivityKind(t, task.Store, "llm_stall"); n != 1 {
		t.Fatalf("llm_stall activities = %d, want 1", n)
	}
	if e.llmDeadSettle(context.Background(), task) {
		t.Fatal("still below threshold")
	}
	if n := countActivityKind(t, task.Store, "llm_stall"); n != 1 {
		t.Fatalf("llm_stall activities = %d after re-check, want 1 (once per episode)", n)
	}

	// A single successful call vetoes the settle and re-arms the warning.
	insertLLMDeadUsage(t, m, task.ID, "ok", 1)
	insertLLMDeadUsage(t, m, task.ID, "error", 4)
	if e.llmDeadSettle(context.Background(), task) {
		t.Fatal("ok>0 must veto the wind-down")
	}
	if _, still := e.llmStallWarned.Load(task.ID); still {
		t.Fatal("a successful call must re-arm (clear) the stall marker")
	}
	if got := m.TaskStatus(task.ID); got == "timeout" {
		t.Fatalf("task settled despite a live call, status=%q", got)
	}
}

// TestLLMDeadSettleSkipsGoallessTasks — chat-injected tasks are frontier-drain
// owned; the llm-dead guard must skip them exactly like the stagnation guard.
func TestLLMDeadSettleSkipsGoallessTasks(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", t)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("llm-dead goalless", "goalless fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.Store.ID()) })
	insertLLMDeadUsage(t, m, task.ID, "error", 5)
	e := NewEngine(m)
	if e.llmDeadSettle(context.Background(), task) {
		t.Fatal("goalless task must not be llm-dead settled")
	}
}

// TestLLMDeadConfigDefaultsAndOverrides — unset = the 10-minute default with a
// fail-count of 5 (deliberately ON, stagnation posture); "0" opts out; both
// knobs parse.
func TestLLMDeadConfigDefaultsAndOverrides(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", t)
	}
	t.Cleanup(func() { _ = m.Close() })
	clear := func() {
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key IN ('llm_dead_window_minutes','llm_dead_min_failures')`)
	}
	clear()
	t.Cleanup(clear)

	if win, fails := m.LLMDeadConfig(); win != 10*time.Minute || fails != 5 {
		t.Fatalf("defaults: window=%v fails=%d, want 10m/5", win, fails)
	}
	if err := m.pg.SetSetting(settingLLMDeadWindowMin, "0"); err != nil {
		t.Fatal(err)
	}
	if win, _ := m.LLMDeadConfig(); win != 0 {
		t.Fatalf("explicit 0: window=%v, want 0 (off)", win)
	}
	if err := m.pg.SetSetting(settingLLMDeadWindowMin, "3"); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(settingLLMDeadMinFails, "7"); err != nil {
		t.Fatal(err)
	}
	if win, fails := m.LLMDeadConfig(); win != 3*time.Minute || fails != 7 {
		t.Fatalf("overrides: window=%v fails=%d, want 3m/7", win, fails)
	}
}

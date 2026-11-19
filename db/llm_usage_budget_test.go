package db

import (
	"fmt"
	"testing"
	"time"
)

// TestTaskTotalTokensSumsLedgerAcrossWorkersAndRestarts guards the token-budget
// police meter: the sum must include input+output+cache (billed), add up every
// worker row of the task, and never leak another task's spend.
func TestTaskTotalTokensSumsLedgerAcrossWorkersAndRestarts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UnixNano()
	taskA := fmt.Sprintf("budget-a-%d", suffix)
	taskB := fmt.Sprintf("budget-b-%d", suffix)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id IN ($1,$2)`, taskA, taskB)
	})

	for _, u := range []LLMUsage{
		{TaskID: taskA, Worker: "planner", Model: "m1", InputTokens: 100, OutputTokens: 40, CacheRead: 5, CacheWrite: 2},
		{TaskID: taskA, Worker: "worker", Model: "m2", InputTokens: 300, OutputTokens: 60},
		{TaskID: taskB, Worker: "worker", Model: "m1", InputTokens: 9999},
	} {
		row := u
		if err := d.InsertLLMUsage(&row); err != nil {
			t.Fatal(err)
		}
	}

	gotA, err := d.TaskTotalTokens(taskA)
	if err != nil {
		t.Fatal(err)
	}
	if gotA != 507 {
		t.Fatalf("task A total=%d, want 507 (100+40+5+2 + 300+60)", gotA)
	}
	gotB, err := d.TaskTotalTokens(taskB)
	if err != nil {
		t.Fatal(err)
	}
	if gotB != 9999 {
		t.Fatalf("task B total=%d, want 9999", gotB)
	}
	missing, err := d.TaskTotalTokens(fmt.Sprintf("absent-%d", suffix))
	if err != nil || missing != 0 {
		t.Fatalf("absent task total=%d err=%v, want 0/nil", missing, err)
	}
}

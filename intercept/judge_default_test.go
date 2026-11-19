package intercept

import "testing"

// Pins the fail-closed judge default (see intercept.go: judge defaults). When the
// judge model errors or replies unparseably, an unset llm_judge_fail_action must
// DENY. judgeConfig resolution itself needs a live DB, so this guards the
// constant an accidental revert to the upstream "allow" default would change.
func TestDefaultJudgeFailActionIsDeny(t *testing.T) {
	if defaultJudgeFailAction != "deny" {
		t.Fatalf("defaultJudgeFailAction = %q, want %q (fail-closed contract)", defaultJudgeFailAction, "deny")
	}
}

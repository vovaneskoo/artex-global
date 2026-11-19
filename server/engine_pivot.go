package server

// Wall detector → planner pivot nudge. Motivated by the 2026-11-18/19 bench
// night (task 11): after the auth surface converged at 02:51, the planner spent
// ~7 more hours issuing "close the final open edge" intents — its own prompt
// FORCES it to produce an intent whenever the frontier is empty and goals are
// unmet, so a converged-but-unmet goal turns into an intent mill. The
// stagnation wind-down (engine_timeout.go) eventually stops the bleed; this
// detector makes the planner USE those rounds: on a wall signal it must either
// find a genuinely untried angle WITHIN the task scope, or hand down a verdict
// (a documented wall is a valid result). Together with the add_intent
// exhausted-anchor guard, the loop "re-dispatch the same last edge" is closed
// from both ends: the guard rejects it, the nudge says what to do instead.

import (
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
)

const (
	// pivotDryRounds arms the nudge after this many consecutive planner rounds
	// where workers finished (done/finding triggers present) but the task's
	// finding count did not move. 3 rounds ≈ 20–40 min of grinding at the
	// night's pace.
	pivotDryRounds = 3
	// pivotMinInterval spaces consecutive nudges so the planner gets time to
	// act on the previous one before being told again.
	pivotMinInterval = 20 * time.Minute
	// pivotMaxPerTask caps the nudges; the last one carries the "conclude now"
	// instruction (verdict or prove_goal — stop producing verification intents).
	pivotMaxPerTask = 3
)

// pivotState is per-task, mutated only from the task's plannerLoop goroutine
// (runRound is its sole caller), so no extra locking is needed beyond the
// sync.Map that holds the pointers.
type pivotState struct {
	lastFindings int64
	dry          int
	lastNudge    time.Time
	nudges       int
}

// newPivotState seeds lastFindings with a sentinel so the first observed round
// always initializes the counter instead of counting as a dry round.
func newPivotState() *pivotState { return &pivotState{lastFindings: -1} }

// pivotDecision is the pure state step: feed it the task's current finding
// count and it updates the dry-streak / nudge bookkeeping. Returns whether a
// "pivot" trigger should be injected this round, and whether it is the final
// one (conclude-now instruction).
func pivotDecision(st *pivotState, findings int64, now time.Time) (nudge, final bool) {
	if findings != st.lastFindings {
		st.lastFindings = findings
		st.dry = 0
		return false, false
	}
	st.dry++
	if st.dry < pivotDryRounds || st.nudges >= pivotMaxPerTask ||
		!st.lastNudge.IsZero() && now.Sub(st.lastNudge) < pivotMinInterval {
		return false, false
	}
	st.nudges++
	st.lastNudge = now
	return true, st.nudges >= pivotMaxPerTask
}

// maybePivotTrigger appends a "pivot" trigger event when the task is grinding
// (workers finishing, no new findings). Best-effort: any error just skips the
// check for this round. Only called from runRound with non-empty triggers.
func (e *Engine) maybePivotTrigger(t *Task, triggers []agent.TriggerEvent) []agent.TriggerEvent {
	if e.m == nil || e.m.pg == nil {
		return triggers
	}
	hasWork := false
	for _, tr := range triggers {
		if tr.Kind == "done" || tr.Kind == "finding" {
			hasWork = true
			break
		}
	}
	if !hasWork {
		return triggers // bare heartbeat wake: nothing finished, no dry signal
	}
	taskNum, err := parseTaskID(t.ID)
	if err != nil {
		return triggers
	}
	findings, err := e.m.pg.FindingsCount(taskNum)
	if err != nil {
		return triggers
	}
	v, _ := e.pivot.LoadOrStore(t.ID, newPivotState())
	st := v.(*pivotState)
	nudge, final := pivotDecision(st, findings, time.Now())
	if !nudge {
		return triggers
	}
	detail := fmt.Sprintf("已连续 %d 轮意图收场而零新 finding(第 %d/%d 次碰壁提示)", st.dry, st.nudges, pivotMaxPerTask)
	if final {
		detail += "——这是最后一次提示:本轮要么产出 scope 内真正未试过的新角度,要么给出目标的最终判定"
	}
	log.Printf("[pivot] task %s %s", t.ID, detail)
	return append(triggers, agent.TriggerEvent{Kind: "pivot", Detail: detail})
}

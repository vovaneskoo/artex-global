package server

// Task token-budget police (consumed by engine_timeout.go). Follows the same
// pattern as manager_stagnation.go: a plain settings integer consumed by the
// engine coordinator, default off so upstream behavior is unchanged.

import "strconv"
import "strings"

const (
	// settingTaskTokenBudget is a task's total LLM token budget (input+output,
	// cache reads counted too since they cost money). 0 / unset = unlimited.
	// The always-on llm_usage ledger is the source of truth, so the budget is
	// accurate across pool rotation and restarts. A task that exceeds the
	// budget is wound down through the settle sequence with the
	// budget_exhausted cancel cause; its terminal status is timeout.
	settingTaskTokenBudget = "task_token_budget"
	// maxTaskTokenBudget keeps an obviously-wrong value (billions) from
	// wedging tasks on a token count that can never be reached anyway.
	maxTaskTokenBudget = 1_000_000_000
)

// TaskTokenBudget returns the per-task LLM token budget (0 = disabled).
func (m *Manager) TaskTokenBudget() int64 {
	if m == nil || m.pg == nil {
		return 0
	}
	v, _, err := m.pg.GetSetting(settingTaskTokenBudget)
	if err != nil || strings.TrimSpace(v) == "" {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	if n > maxTaskTokenBudget {
		n = maxTaskTokenBudget
	}
	return n
}

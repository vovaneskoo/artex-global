package server

import "time"

// LLM-dead detector settings, following manager_budget.go's pattern: plain
// settings integers consumed by the engine coordinator, defaults sane, 0 window
// disables the detector so upstream behavior is unchanged until opted in.
const (
	// settingLLMDeadWindowMin is the trailing window in minutes over which failed
	// LLM calls are counted. 0 / unset = detector off.
	settingLLMDeadWindowMin = "llm_dead_window_minutes"
	// settingLLMDeadMinFails is how many failed calls within the window (with zero
	// successful ones) count as "the whole LLM chain is dead". 0 = default 5.
	settingLLMDeadMinFails = "llm_dead_min_failures"
)

const (
	llmDeadWindowDefault   = 10 * time.Minute
	llmDeadMinFailsDefault = int64(5)
)

// LLMDeadConfig returns the detector's (window, minFailedCalls); window 0 = off.
func (m *Manager) LLMDeadConfig() (time.Duration, int64) {
	if m == nil || m.pg == nil {
		return 0, llmDeadMinFailsDefault
	}
	winMin, _, err := m.pg.GetSetting(settingLLMDeadWindowMin)
	if err != nil {
		return 0, llmDeadMinFailsDefault
	}
	mins := parseIntSetting(winMin, -1)
	if mins == 0 {
		return 0, llmDeadMinFailsDefault // explicitly off
	}
	if mins < 0 {
		mins = int(llmDeadWindowDefault / time.Minute)
	}
	if mins < 1 {
		mins = 1
	}
	minFails := llmDeadMinFailsDefault
	if v, _, err := m.pg.GetSetting(settingLLMDeadMinFails); err == nil {
		if n := parseIntSetting(v, 0); n > 0 {
			minFails = int64(n)
		}
	}
	return time.Duration(mins) * time.Minute, minFails
}

// parseIntSetting parses a settings integer; fallback when empty/garbage.
func parseIntSetting(v string, fallback int) int {
	n := 0
	neg := false
	i := 0
	if i < len(v) && (v[i] == '-' || v[i] == '+') {
		neg = v[i] == '-'
		i++
	}
	digits := false
	for ; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return fallback
		}
		digits = true
		n = n*10 + int(v[i]-'0')
	}
	if !digits {
		return fallback
	}
	if neg {
		n = -n
	}
	return n
}

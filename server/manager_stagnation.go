package server

// Stagnation wind-down setting (consumed by engine_timeout.go). Kept in its own
// file so the change stays separable from unrelated in-flight work in
// manager.go — same package, same access pattern as settingTaskDefaultTimeout.

import (
	"strconv"
	"strings"
	"time"
)

const (
	// settingTaskStagnation is the no-new-findings window (seconds) after which a
	// running mission is wound down through the ordinary settle sequence even when
	// its wall-clock deadline hasn't fired (or it has timeout=0). Motivated by the
	// 2026-11-18/19 bench night: task 11 produced its last finding at 02:51 and
	// then burned ~7 more hours re-verifying closed edges — findings are the
	// mission's output, so "no findings for hours" is the cheapest reliable dry
	// signal. A stored "0" disables the wind-down (truly unlimited recon).
	settingTaskStagnation = "task_stagnation_seconds"
	// defaultTaskStagnationSeconds is used when the setting is unset/invalid (3h).
	defaultTaskStagnationSeconds = 3 * 3600
	maxTaskStagnationSeconds     = 7 * 24 * 3600
)

// TaskStagnationWindow returns the no-new-findings window that triggers the
// stagnation wind-down (0 = disabled).
func (m *Manager) TaskStagnationWindow() time.Duration {
	if m == nil || m.pg == nil {
		return defaultTaskStagnationSeconds * time.Second
	}
	v, _, err := m.pg.GetSetting(settingTaskStagnation)
	if err != nil || strings.TrimSpace(v) == "" {
		return defaultTaskStagnationSeconds * time.Second
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return defaultTaskStagnationSeconds * time.Second
	}
	if n > maxTaskStagnationSeconds {
		n = maxTaskStagnationSeconds
	}
	return time.Duration(n) * time.Second
}

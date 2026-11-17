package db

import (
	"testing"

	"github.com/Autumn-27/artex/config"
)

// TestOriginFactSummaryLocalized (QA finding): the origin fact's summary is
// rendered in the task feed card, so it must follow the active output language
// instead of the hardcoded Chinese "任务起点：…；目标：…". Every language must
// interpolate both the description and the goal.
func TestOriginFactSummaryLocalized(t *testing.T) {
	prev := config.CurrentLanguage
	defer func() { config.CurrentLanguage = prev }()

	cases := map[string]string{
		"ru": "Начало задачи: D; цель: G",
		"en": "Task origin: D; goal: G",
		"zh": "任务起点：D；目标：G",
		"ja": "タスク開始: D; 目標: G",
		"es": "Inicio de la tarea: D; objetivo: G",
		"ko": "작업 시작: D; 목표: G",
	}
	for lang, want := range cases {
		config.CurrentLanguage = func() string { return lang }
		if got := originFactSummary("D", "G"); got != want {
			t.Errorf("lang %s: originFactSummary = %q, want %q", lang, got, want)
		}
	}
}

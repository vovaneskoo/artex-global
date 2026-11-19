package server

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/Autumn-27/artex/config"
)

// TestTrMsgSwitchesLanguage pins the backend output-language switching: a
// user-facing Korean message is returned verbatim under ko (and when unwired),
// and translated to a non-Korean string under en/zh/es. This is the backend
// analogue of the web i18n catalog — it proves writeErr responses follow the
// configured language, not Korean only.
func TestTrMsgSwitchesLanguage(t *testing.T) {
	t.Cleanup(func() { config.CurrentLanguage = nil })

	hasHangul := func(s string) bool {
		for _, r := range s {
			if unicode.Is(unicode.Hangul, r) {
				return true
			}
		}
		return false
	}

	// A representative catalog key (an existing server error constant value).
	const koMsg = errAssetIDRequired
	if !hasHangul(koMsg) {
		t.Fatalf("precondition: source message should be Korean, got %q", koMsg)
	}

	// Unwired → ko passthrough.
	config.CurrentLanguage = nil
	if got := trMsg(koMsg); got != koMsg {
		t.Fatalf("unwired: trMsg must pass through Korean, got %q", got)
	}

	// ko → passthrough (the key itself).
	config.CurrentLanguage = func() string { return "ko" }
	if got := trMsg(koMsg); got != koMsg {
		t.Fatalf("ko: trMsg must return the Korean source, got %q", got)
	}

	// en/zh/es → a translated, non-empty string. en and es must carry no Hangul.
	for _, lang := range []string{"en", "zh", "es"} {
		config.CurrentLanguage = func() string { return lang }
		got := trMsg(koMsg)
		if got == "" || got == koMsg {
			t.Fatalf("%s: trMsg must translate away from the Korean source, got %q", lang, got)
		}
		if (lang == "en" || lang == "es") && hasHangul(got) {
			t.Fatalf("%s: translation must not contain Hangul, got %q", lang, got)
		}
	}

	// Unknown language code → ko fallback (config.NormalizeLanguage rejects it).
	config.CurrentLanguage = func() string { return "fr" }
	if got := trMsg(koMsg); got != koMsg {
		t.Fatalf("unknown lang: trMsg must fall back to Korean, got %q", got)
	}

	// A string not in the catalog (propagated lower-layer error) passes through.
	config.CurrentLanguage = func() string { return "en" }
	const notInCatalog = "some-lower-layer-error: connection refused"
	if got := trMsg(notInCatalog); got != notInCatalog {
		t.Fatalf("non-catalog string must pass through unchanged, got %q", got)
	}
}

// TestDefaultTaskDescriptionLocalized: the placeholder stored for a task
// created without a description must follow the active output language —
// previously it was the hardcoded Chinese "未命名任务", which leaked into the
// operator's mission list under ru/en UI (QA finding on the operator page).
func TestDefaultTaskDescriptionLocalized(t *testing.T) {
	cases := map[string]string{
		"ru": "Задача без названия",
		"en": "Unnamed task",
		"zh": "未命名任务",
		"ja": "名前のないタスク",
		"es": "Tarea sin nombre",
		"ko": "이름 없는 작업",
	}
	for lang, want := range cases {
		s := &Server{}
		s.outputLang.Store(lang)
		if got := s.defaultTaskDescription(); got != want {
			t.Errorf("lang %s: defaultTaskDescription = %q, want %q", lang, got, want)
		}
	}
}

// TestSeedIntentSummaryFmtLocalized: the seed-intent summary template must
// follow the active output language AND keep exactly two %s verbs in every
// language — a missing verb would make fmt.Sprintf fail at mission creation.
func TestSeedIntentSummaryFmtLocalized(t *testing.T) {
	for _, lang := range []string{"ru", "en", "zh", "ja", "es", "ko"} {
		s := &Server{}
		s.outputLang.Store(lang)
		tpl := s.seedIntentSummaryFmt()
		if strings.Count(tpl, "%s") != 2 {
			t.Errorf("lang %s: template %q must contain exactly two %%s verbs", lang, tpl)
		}
	}
	s := &Server{}
	s.outputLang.Store("ru")
	got := fmt.Sprintf(s.seedIntentSummaryFmt(), "цель", "описание")
	if !strings.Contains(got, "цель") || !strings.Contains(got, "описание") {
		t.Errorf("ru template did not interpolate both fields: %q", got)
	}
	if strings.Contains(got, "任务") {
		t.Errorf("ru template still contains Chinese: %q", got)
	}
}

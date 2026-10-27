package server

import (
	"log"
	"strings"
)

// Skills-mode values a task/agent profile can carry. Empty (inherit) and full
// both mean "no filtering — everything visible"; the difference is only where
// the value came from (unset vs. explicitly chosen). custom takes its skill
// list from the caller-supplied names.
const (
	SkillModeInherit  = ""         // inherit: everything visible, no filter
	SkillModeRecon    = "recon"    // read-only recon preset
	SkillModeStandard = "standard" // recon + assault / initial-access basics
	SkillModeFull     = "full"     // everything visible, explicitly chosen
	SkillModeCustom   = "custom"   // explicit list of skill names
)

// skillModeExtras are the post-standard skills that no preset names — only a
// custom list can select them individually.
var skillModeExtras = []string{
	"host-evasion",
	"privesc-lateral-persistence",
	"db-post-exploit",
	"mobile-app-assessment",
	"autonomy-budget-pacing",
	"datasource-proxy-sql",
}

// skillModeBuiltins are the skills shipped on the filesystem (skills/), always
// candidates for a custom list.
var skillModeBuiltins = []string{"playwright-cli", "api-recon", "scopesentry"}

// skillsModeRecon is the recon-only preset: passive/recon work plus the skills
// that shape findings into a report.
var skillsModeRecon = []string{
	"web-recon",
	"engagement-workspace",
	"email-verification-autonomy",
	"finding-quality-reporting",
	"deliverable-engineering",
}

// skillModePresets maps a preset mode to its fixed skill allowlist (directory
// names under SkillDir). standard = recon + the assault / initial-access set.
var skillModePresets = map[string][]string{
	SkillModeRecon: skillsModeRecon,
	SkillModeStandard: append(append([]string{}, skillsModeRecon...),
		"web-assault",
		"api-assault",
		"creds-initial-access",
		"exploit-search",
		"opsec-decoy-detect",
		"admin-panel-abuse",
	),
}

// knownSkillNames is every skill name the server may recognize: both presets,
// the custom-only extras, and the filesystem builtins. Used solely to warn
// about likely typos in a custom list — unknown names are kept, never dropped,
// so user-installed skills still work.
var knownSkillNames = func() map[string]bool {
	m := map[string]bool{}
	for _, names := range skillModePresets {
		for _, n := range names {
			m[n] = true
		}
	}
	for _, n := range append(append([]string{}, skillModeExtras...), skillModeBuiltins...) {
		m[n] = true
	}
	return m
}()

// ValidSkillMode reports whether mode is one of the known skills-mode values.
func ValidSkillMode(mode string) bool {
	_, ok := EffectiveSkillSet(mode, nil)
	return ok
}

// EffectiveSkillSet resolves a skills mode into the effective allowlist. A nil
// allowlist means "do not filter" (every visible skill); a non-nil one limits
// the palette to its keys. Preset modes build a fresh map per call (callers may
// mutate it); custom names are trimmed and de-duplicated, and names outside
// knownSkillNames are kept but logged once as a warning. ok is false when mode
// is not a known skills mode.
func EffectiveSkillSet(mode string, custom []string) (allowlist map[string]bool, ok bool) {
	switch mode {
	case SkillModeInherit, SkillModeFull:
		return nil, true
	case SkillModeRecon, SkillModeStandard:
		preset := skillModePresets[mode]
		allow := make(map[string]bool, len(preset))
		for _, n := range preset {
			allow[n] = true
		}
		return allow, true
	case SkillModeCustom:
		allow := make(map[string]bool, len(custom))
		var unknown []string
		for _, n := range custom {
			n = strings.TrimSpace(n)
			if n == "" || allow[n] {
				continue
			}
			if !knownSkillNames[n] {
				unknown = append(unknown, n)
			}
			allow[n] = true
		}
		if len(unknown) > 0 {
			log.Printf("[skills-mode] custom: unknown skill names kept anyway: %s", strings.Join(unknown, ", "))
		}
		return allow, true
	default:
		return nil, false
	}
}

// FilterSkillPalette intersects a skill palette with an allowlist. A nil allow
// passes everything through; otherwise only allowed names survive, preserving
// input order. Always returns a fresh slice — never the caller's.
func FilterSkillPalette(names []string, allow map[string]bool) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if allow == nil || allow[n] {
			out = append(out, n)
		}
	}
	return out
}

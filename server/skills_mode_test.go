package server

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"testing"
)

// sameSet reports whether the key set of got equals want exactly.
func sameSet(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, n := range want {
		if !got[n] {
			return false
		}
	}
	return true
}

// TestEffectiveSkillSetModes covers every skills mode: inherit/full resolve to
// a nil allowlist (no filtering), the presets to their exact fixed sets, and an
// unknown mode to ok=false.
func TestEffectiveSkillSetModes(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		want    []string // nil+wantNil → expect nil allowlist
		wantNil bool
	}{
		{name: "inherit empty mode", mode: SkillModeInherit, wantNil: true},
		{name: "full", mode: SkillModeFull, wantNil: true},
		{
			name: "recon",
			mode: SkillModeRecon,
			want: []string{
				"web-recon", "engagement-workspace", "email-verification-autonomy",
				"finding-quality-reporting", "deliverable-engineering",
			},
		},
		{
			name: "standard is recon + assault set",
			mode: SkillModeStandard,
			want: []string{
				"web-recon", "engagement-workspace", "email-verification-autonomy",
				"finding-quality-reporting", "deliverable-engineering",
				"web-assault", "api-assault", "creds-initial-access",
				"exploit-search", "opsec-decoy-detect", "admin-panel-abuse",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, ok := EffectiveSkillSet(tc.mode, nil)
			if !ok {
				t.Fatalf("EffectiveSkillSet(%q) ok = false, want true", tc.mode)
			}
			if tc.wantNil {
				if allow != nil {
					t.Fatalf("EffectiveSkillSet(%q) = %v, want nil allowlist", tc.mode, allow)
				}
				return
			}
			if !sameSet(allow, tc.want) {
				t.Fatalf("EffectiveSkillSet(%q) = %v, want exactly %v", tc.mode, allow, tc.want)
			}
		})
	}

	if allow, ok := EffectiveSkillSet(" aggressive ", nil); ok || allow != nil {
		t.Fatalf("EffectiveSkillSet(garbage) = (%v, %v), want (nil, false)", allow, ok)
	}
	if !ValidSkillMode("standard") || ValidSkillMode("nope") {
		t.Fatal("ValidSkillMode disagrees with EffectiveSkillSet")
	}
}

// TestEffectiveSkillSetPresetCopy ensures each preset call returns its own map:
// mutating one result must not leak into later calls or the stored preset.
func TestEffectiveSkillSetPresetCopy(t *testing.T) {
	first, ok := EffectiveSkillSet(SkillModeRecon, nil)
	if !ok {
		t.Fatal("recon mode not ok")
	}
	first["injected-skill"] = true

	second, _ := EffectiveSkillSet(SkillModeRecon, nil)
	if second["injected-skill"] {
		t.Fatal("allowlist shared between calls: mutating one leaked into the next")
	}
}

// TestEffectiveSkillSetCustom covers the custom mode: names are trimmed and
// de-duplicated, unknown names are kept (not dropped) and reported in exactly
// one warning line.
func TestEffectiveSkillSetCustom(t *testing.T) {
	var buf bytes.Buffer
	// Save/restore the ORIGINAL writer+flags: log.SetOutput(nil) stores a literal
	// nil writer (Go 1.26 log.go SetOutput), and the next global log.Printf in any
	// later test SIGSEGVs on l.out.Write — restore the real sink, never nil.
	oldW, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(oldW); log.SetFlags(oldFlags) })

	allow, ok := EffectiveSkillSet(SkillModeCustom, []string{
		"  web-recon  ", "host-evasion", "web-recon", "totally-new-skill", "", "  ", "host-evasion",
	})
	if !ok {
		t.Fatal("custom mode not ok")
	}
	want := []string{"web-recon", "host-evasion", "totally-new-skill"}
	if !sameSet(allow, want) {
		t.Fatalf("custom allowlist = %v, want %v (unknown kept, dupes collapsed)", allow, want)
	}

	warn := strings.Count(buf.String(), "[skills-mode]")
	if warn != 1 {
		t.Fatalf("got %d warning line(s) %q, want exactly 1", warn, buf.String())
	}
	if !strings.Contains(buf.String(), "totally-new-skill") {
		t.Fatalf("warning %q does not list the unknown name", buf.String())
	}
}

// TestFilterSkillPalette covers the palette intersection: nil allow passes
// everything through (as a copy), a set allow keeps order and drops the rest.
func TestFilterSkillPalette(t *testing.T) {
	palette := []string{"web-recon", "web-assault", "playwright-cli", "deliverable-engineering"}

	// nil allow → everything, in a fresh slice.
	all := FilterSkillPalette(palette, nil)
	if !reflect.DeepEqual(all, palette) {
		t.Fatalf("nil allow: got %v, want %v", all, palette)
	}
	all[0] = "mutated"
	if palette[0] != "web-recon" {
		t.Fatal("nil allow: result aliases the input slice")
	}

	// allow filter → only allowed names, input order preserved.
	allow, _ := EffectiveSkillSet(SkillModeRecon, nil)
	got := FilterSkillPalette(palette, allow)
	want := []string{"web-recon", "deliverable-engineering"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recon allow: got %v, want %v", got, want)
	}

	// empty palette → empty result.
	if out := FilterSkillPalette(nil, allow); len(out) != 0 {
		t.Fatalf("empty palette: got %v, want empty", out)
	}
}

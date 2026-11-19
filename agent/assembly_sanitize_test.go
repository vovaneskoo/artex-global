package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSanitizeControlChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii unchanged", "hello world", "hello world"},
		{"tab lf cr preserved", "line1\tTab\nline2\r\nline3", "line1\tTab\nline2\r\nline3"},
		{"null byte replaced", "a\x00b", "a�b"},
		{"mixed c0 controls", "\x01\x02\x03visible\x1b[0m", "���visible�[0m"},
		{"del 0x7f replaced", "a\x7fb", "a�b"},
		{"c1 u+0080 replaced", "a\u0080b", "a�b"},
		{"c1 u+009f replaced", "a\u009fb", "a�b"},
		{"multibyte utf8 kept", "по-русски + 中文 + emoji 🎯", "по-русски + 中文 + emoji 🎯"},
		{"invalid utf8 replaced", "a\xff\xfeb", "a��b"},
		{"binary urandom head", "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 8), "�ELF" + strings.Repeat("�", 12)},
		{"empty string", "", ""},
		// A literal backslash-u escape sequence is 6 printable chars, not a raw
		// control byte: it is already JSON-safe and must pass through untouched.
		{"literal escape text kept", `{"k":"v\u0000w"}`, `{"k":"v\u0000w"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeControlChars(tc.in)
			if got != tc.want {
				t.Errorf("SanitizeControlChars(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsRune(got, 0) {
				t.Errorf("result still contains NUL: %q", got)
			}
		})
	}
}

// The sanitizer must be idempotent: sanitized history is re-fed through it on
// resumed sessions.
func TestSanitizeControlCharsIdempotent(t *testing.T) {
	in := "x\x00y\x01\u0080\xffz"
	once := SanitizeControlChars(in)
	twice := SanitizeControlChars(once)
	if once != twice {
		t.Errorf("not idempotent: %q vs %q", once, twice)
	}
}

// The whole point of the fix: sanitized output must be embeddable in the JSON
// request body without the provider rejecting it. json.Marshal never emits a
// raw NUL after sanitization.
func TestSanitizeControlCharsJSONSafe(t *testing.T) {
	raw := "\x00\x01\x02binary\xff\xfe" + strings.Repeat("\x00", 64)
	safe := SanitizeControlChars(raw)
	b, err := json.Marshal(safe)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "\x00") {
		t.Fatal("marshaled body still contains a raw NUL byte")
	}
}

// sanitizeToolResult must reach text blocks, nested tool_result content, and
// the Extra messages tools can inject after their result.
func TestSanitizeToolResultCoversAllSurfaces(t *testing.T) {
	res := actool.Result{
		Content: []llm.ContentBlock{
			llm.TextBlock("top\x00level"),
			{Type: llm.BlockToolResult, ToolUseID: "t1", Content: []llm.ContentBlock{
				llm.TextBlock("nested\x01"),
			}},
		},
		Extra: []llm.Message{
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("extra\x02msg")}},
		},
	}
	out := sanitizeToolResult(res)
	if got := out.Content[0].Text; got != "top�level" {
		t.Errorf("text block: got %q", got)
	}
	if got := out.Content[1].Content[0].Text; got != "nested�" {
		t.Errorf("nested block: got %q", got)
	}
	if got := out.Extra[0].Content[0].Text; got != "extra�msg" {
		t.Errorf("extra message: got %q", got)
	}
}

// A tool that returns binary output must come back sanitized when invoked
// through the AugmentTools pipeline (guardPanic wraps every tool).
func TestGuardedToolSanitizesBinaryOutput(t *testing.T) {
	binary := []byte{0x00, 'h', 'i', 0x01, 0xff, 0x7f}
	tool := readTool("spew", "spews binary", map[string]any{},
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return actool.Text(string(binary)), nil
		})
	wrapped := guardPanic(tool)
	res, err := wrapped.Call(context.Background(), json.RawMessage("{}"), nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	got := res.Flatten()
	if strings.ContainsRune(got, 0) {
		t.Fatalf("tool output still carries NUL: %q", got)
	}
	want := "�" + "hi" + "�" + "�" + "�"
	if got != want {
		t.Errorf("sanitized output = %q, want %q", got, want)
	}
}

// A panicking tool must still yield an error result (pre-existing guardPanic
// behavior must survive the sanitize addition).
func TestGuardedToolStillCatchesPanic(t *testing.T) {
	tool := readTool("boom", "panics", map[string]any{},
		func(context.Context, json.RawMessage) (actool.Result, error) {
			panic("kaboom")
		})
	wrapped := guardPanic(tool)
	res, err := wrapped.Call(context.Background(), json.RawMessage("{}"), nil)
	if err != nil {
		t.Fatalf("call err: %v", err)
	}
	if !res.IsError {
		t.Error("panic must map to an error result")
	}
}

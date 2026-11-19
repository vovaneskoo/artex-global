package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Кейс с бенча: бинарный вывод инструмента с NUL и control-байтами не должен
// попадать в историю сообщений (Venice 400 «String must not contain null bytes»).
func TestSanitizeToolResultDropsNullBytes(t *testing.T) {
	res := actool.Result{Content: []llm.ContentBlock{
		{Type: llm.BlockText, Text: "header\x00\x00binary\x00tail\nline2"},
	}}
	out := SanitizeToolResult(res)
	got := out.Content[0].Text
	if strings.ContainsRune(got, 0) {
		t.Fatalf("NUL остался: %q", got)
	}
	if got != "headerbinarytail\nline2" {
		t.Fatalf("ожидали точную очистку, получили %q", got)
	}
}

func TestSanitizeToolResultKeepsWhitespace(t *testing.T) {
	in := "col1\tcol2\nrow2\r\nindent  "
	out := SanitizeToolResult(actool.Result{Content: []llm.ContentBlock{
		{Type: llm.BlockText, Text: in},
	}})
	if out.Content[0].Text != in {
		t.Fatalf("обычный текст изменён: %q", out.Content[0].Text)
	}
}

func TestSanitizeToolResultControlsToSpace(t *testing.T) {
	out := SanitizeToolResult(actool.Result{Content: []llm.ContentBlock{
		{Type: llm.BlockText, Text: "a\x01\x02\x03b\x7fc"},
	}})
	if out.Content[0].Text != "a   b c" {
		t.Fatalf("control-символы не заменены: %q", out.Content[0].Text)
	}
}

func TestSanitizeToolResultSkipsNonTextBlocks(t *testing.T) {
	res := actool.Result{Content: []llm.ContentBlock{
		{Type: llm.BlockCompactBoundary, Text: "\x00"},
		{Type: llm.BlockText, Text: "clean"},
	}}
	out := SanitizeToolResult(res)
	if out.Content[0].Text != "\x00" {
		t.Fatalf("нетекстовый блок не должен менятьcя: %q", out.Content[0].Text)
	}
	if out.Content[1].Text != "clean" {
		t.Fatalf("чистый текст изменился: %q", out.Content[1].Text)
	}
}

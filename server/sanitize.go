package server

import (
	"strings"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// SanitizeToolResult вычищает из tool_result управляющие символы, которые
// отвергают LLM-API (Venice/OpenAI: 400 «String must not contain null bytes»).
// Бинарный вывод инструмента (дампы файлов, байты протоколов) иначе отравляет
// историю диалога навсегда: каждый повтор запроса с испорченной историей
// отклоняется, интент умирает (bench 2026-10-23, task 2 intent #10).
// \t \n \r сохраняются; NUL удаляется; прочие C0 и DEL → пробел. Thinking-блоки
// не трогаем — они модельные, не инструментальные, и защищены подписью.
func SanitizeToolResult(res actool.Result) actool.Result {
	for i := range res.Content {
		if res.Content[i].Type == llm.BlockText && needsSanitize(res.Content[i].Text) {
			res.Content[i].Text = sanitizeText(res.Content[i].Text)
		}
	}
	return res
}

func needsSanitize(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f
	}) >= 0
}

func sanitizeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0:
			// NUL — валим веником: именно он ломает JSON-сериализацию запроса
		case (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

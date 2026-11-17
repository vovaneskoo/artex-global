package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// containsHan 은 문자열에 CJK 한자(중국어)가 섞여 있으면 true 를 돌려준다.
// 한글(unicode.Hangul)·영문·숫자·기호는 한자가 아니므로 걸리지 않는다.
func containsHan(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return r, true
		}
	}
	return 0, false
}

func sampleFindingNode(t *testing.T) *db.Node {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"vulnclass": "SQL Injection",
		"name":      "로그인 폼 SQL 주입",
		"severity":  "high",
		"summary":   "로그인 파라미터에서 오류 기반 SQL 주입이 확인되었습니다.",
		"evidence":  map[string]string{"poc": "' OR '1'='1"},
	})
	if err != nil {
		t.Fatalf("payload 직렬화 실패: %v", err)
	}
	return &db.Node{ID: 1, Kind: "finding", Payload: payload}
}

func sampleDBFinding() *db.DBFinding {
	return &db.DBFinding{
		ID:              123,
		VulnClass:       "SQL Injection",
		Name:            "로그인 폼 SQL 주입",
		Severity:        "high",
		Summary:         "로그인 파라미터에서 오류 기반 SQL 주입이 확인되었습니다.",
		Evidence:        "' OR '1'='1",
		Status:          "confirmed",
		Report:          "상세 분석 본문.",
		CreatedAt:       time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		EvidenceVersion: 2,
		TaskDescription: "데모 대상 침투 테스트",
		TrafficBindings: []db.FindingTrafficBinding{
			{
				ID:   9,
				Role: "request",
				Note: "주입 페이로드 전송 지점",
				Snapshot: db.TrafficEvidenceSnapshot{
					Method: "POST",
					URL:    "https://sandbox.local/login",
					Status: 200,
				},
			},
		},
	}
}

// TestReportMarkdownLocalized 는 탐색 그래프 보고서(report.Markdown)의 골격이 한국어이고
// 중국어 한자가 전혀 없음을 검증한다.
func TestReportMarkdownLocalized(t *testing.T) {
	out := Markdown(Input{
		Title:       "데모 작업",
		Goal:        "샌드박스 전수 점검",
		GeneratedAt: time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		Locale:      "ko",
		AssetCounts: map[string]int{"host": 2, "url": 5},
		Findings:    []*db.Node{sampleFindingNode(t)},
	})
	if r, ok := containsHan(out); ok {
		t.Fatalf("보고서 골격에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# 침투 테스트 보고서: 데모 작업",
		"- **작업 목표**: 샌드박스 전수 점검",
		"- **생성 시각**:",
		"## 요약",
		"- 확인된 취약점: **1**건",
		"## 확인된 취약점",
		"증거 참조:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("보고서 골격에 %q 가 없다", want)
		}
	}
}

// TestReportMarkdownEmptyLocalized 는 취약점이 없을 때의 안내 문구가 한국어이고,
// '점검하지 않았다'가 아니라 '확정된 취약점이 없을 뿐, 안전의 증거는 아님'을 말하는지 검증한다.
func TestReportMarkdownEmptyLocalized(t *testing.T) {
	out := Markdown(Input{Title: "빈 작업", GeneratedAt: time.Now(), Locale: "ko"})
	if r, ok := containsHan(out); ok {
		t.Fatalf("빈 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	if !strings.Contains(out, "확정된 취약점은 기록되지 않았습니다") {
		t.Errorf("빈 보고서 안내 문구가 한국어가 아니다:\n%s", out)
	}
	if !strings.Contains(out, "안전하다는 증거가 아닙니다") {
		t.Errorf("빈 보고서가 안전 증명처럼 읽힌다:\n%s", out)
	}
}

// TestFindingsMarkdownLocalized 는 취약점 요약/상세 Markdown 익스포트 골격과 심각도 라벨이
// 한국어이고 중국어 한자가 없음을 검증한다.
func TestFindingsMarkdownLocalized(t *testing.T) {
	f := sampleDBFinding()
	out := FindingsMarkdown([]*db.DBFinding{f}, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC), "ko")
	if r, ok := containsHan(out); ok {
		t.Fatalf("취약점 요약 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# 취약점 요약 보고서",
		"- **생성 시각**:",
		"- **취약점 총계**: 1건",
		"## 요약",
		"| 심각도 | 개수 |",
		"| 심각 |", "| 높음 |", "| 중간 |", "| 낮음 |", // 심각도 라벨(UI status.severity 와 동일)
		"## 취약점 상세",
		"- **유형**: SQL Injection",
		"- **상태**: confirmed",
		"- **소속 작업**: 데모 대상 침투 테스트",
		"- **발견 시각**:",
		"**증거:**",
		"**상세 보고서:**",
		"## 관련 트래픽 증거",
		"증거 버전: 2, 바인딩 개수: 1.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("요약 보고서에 %q 가 없다", want)
		}
	}

	single := SingleFindingMarkdown(f, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC), "ko")
	if r, ok := containsHan(single); ok {
		t.Fatalf("단건 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), single)
	}
	for _, want := range []string{
		"- **심각도**: high",
		"## 개요",
		"## 증거",
		"## 상세 보고서",
		"[요청 메시지](evidence/123/9/request.http)",
		"[응답 메시지](evidence/123/9/response.http)",
	} {
		if !strings.Contains(single, want) {
			t.Errorf("단건 보고서에 %q 가 없다", want)
		}
	}
}

// TestFindingsExportRussianLocale (F-04): the findings-page export skeleton —
// summary Markdown, single-finding Markdown and the CSV header — must render
// Russian when the ru locale is active, with no Korean skeleton leftovers and
// no Han characters. Before the locale plumbing these headers were hardcoded
// Korean regardless of the operator's language.
func TestFindingsExportRussianLocale(t *testing.T) {
	f := sampleDBFinding()
	when := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	out := FindingsMarkdown([]*db.DBFinding{f}, when, "ru")
	for _, want := range []string{
		"# Сводный отчёт по находкам",
		"- **Время формирования**:",
		"- **Всего находок**: 1",
		"## Сводка",
		"| Серьёзность | Количество |",
		"| Критическая |", "| Высокая |", "| Средняя |", "| Низкая |",
		"## Детали находок",
		"- **Тип**: SQL Injection",
		"- **Статус**: confirmed",
		"- **Задача**: 데모 대상 침투 테스트",
		"- **Время обнаружения**:",
		"**Доказательство:**",
		"**Подробный отчёт:**",
		"## Связанные доказательства трафика",
		"Версия доказательств: 2, привязок: 1.",
		"**Доказательство #9 · request**: `POST https://sandbox.local/login`, код состояния 200",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ru findings export missing %q:\n%s", want, out)
		}
	}
	if r, ok := containsHan(out); ok {
		t.Errorf("ru findings export contains Han %q:\n%s", string(r), out)
	}

	single := SingleFindingMarkdown(f, when, "ru")
	for _, want := range []string{
		"- **Серьёзность**: high",
		"## Обзор",
		"## Доказательство",
		"## Подробный отчёт",
		"[Сообщение запроса](evidence/123/9/request.http)",
		"[Сообщение ответа](evidence/123/9/response.http)",
	} {
		if !strings.Contains(single, want) {
			t.Errorf("ru single-finding export missing %q:\n%s", want, single)
		}
	}
	if r, ok := containsHan(single); ok {
		t.Errorf("ru single-finding export contains Han %q:\n%s", string(r), single)
	}

	raw := FindingsCSV([]*db.DBFinding{f}, "ru")
	header := strings.SplitN(strings.TrimPrefix(string(raw), "\xEF\xBB\xBF"), "\n", 2)[0]
	for _, col := range []string{"ID", "Название", "Тип", "Серьёзность", "Статус", "Задача", "Время обнаружения", "Обзор", "Кол-во доказательств трафика", "ID доказательств трафика"} {
		if !strings.Contains(header, col) {
			t.Errorf("ru CSV header missing %q: %s", col, header)
		}
	}
	if r, ok := containsHan(header); ok {
		t.Errorf("ru CSV header contains Han %q: %s", string(r), header)
	}

	// Unnamed finding falls back to the locale's "unclassified" word in both the
	// markdown title and the export filename.
	unnamed := &db.DBFinding{ID: 7, Severity: "low"}
	if got := SingleFindingMarkdown(unnamed, when, "ru"); !strings.Contains(got, "Без класса") {
		t.Errorf("ru unnamed finding missing «Без класса»:\n%s", got)
	}
	if got := FindingFilename(unnamed, "ru"); !strings.Contains(got, "Без_класса") {
		t.Errorf("ru filename missing «Без_класса»: %q", got)
	}
}

// TestFindingsExportFallbackLocale: unsupported locales (and the empty locale)
// fall back to the English export skeleton, same rule as the task report.
func TestFindingsExportFallbackLocale(t *testing.T) {
	f := sampleDBFinding()
	when := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	reference := FindingsMarkdown([]*db.DBFinding{f}, when, "en")
	for _, locale := range []string{"", "fr", "EN", "zh", "xx-nonsense"} {
		if got := FindingsMarkdown([]*db.DBFinding{f}, when, locale); got != reference {
			t.Errorf("locale %q did not fall back to the en findings skeleton:\n--- got ---\n%s\n--- en ---\n%s", locale, got, reference)
		}
	}
}

// TestFindingsCSVLocalized 는 CSV 익스포트 헤더가 한국어이고 중국어 한자가 없음을 검증한다.
// (BOM 뒤 헤더 행만 한국어면 된다. 데이터 값은 원본 그대로 둔다.)
func TestFindingsCSVLocalized(t *testing.T) {
	raw := FindingsCSV([]*db.DBFinding{sampleDBFinding()}, "ko")
	out := strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
	header := strings.SplitN(out, "\n", 2)[0]
	if r, ok := containsHan(header); ok {
		t.Fatalf("CSV 헤더에 중국어 한자 %q 가 남아 있다: %s", string(r), header)
	}
	for _, col := range []string{"ID", "이름", "유형", "심각도", "상태", "소속 작업", "발견 시각", "개요", "트래픽 증거 개수", "트래픽 증거 ID"} {
		if !strings.Contains(header, col) {
			t.Errorf("CSV 헤더에 %q 열이 없다: %s", col, header)
		}
	}
}

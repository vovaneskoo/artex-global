package report

import "strings"

// bundle holds every user-facing skeleton string of the task report, per
// locale. Supported: en, ru, ko (report.go bundleFor); unsupported locales
// fall back to en. Keys are fixed wording — format verbs only (e.g. %d, %s),
// never reordered placeholders, so a missing translation can never corrupt the
// layout.
type bundle struct {
	titlePrefix      string // "# <prefix><title>"
	unnamedTask      string
	goalLabel        string
	goalUnset        string
	taskIDLabel      string
	explorationLabel string
	statusLabel      string
	createdLabel     string
	completedLabel   string
	generatedLabel   string

	summaryTitle          string
	confirmedFindingsFmt  string // %d = confirmed findings count
	observedFacts         string
	unverifiedConclusions string
	taskAssetsPrefix      string
	taskAssetsEmpty       string
	inheritedNote         string // %s = "#1, #2" source task list

	findingsTitle string
	// noFindingsHonest is shown when 0 findings were confirmed. It must never
	// read as proof of security: it states what was actually done instead.
	noFindingsHonest string
	evidenceRefFmt   string // %1$d finding id, %2$s status, %3$d traffic bindings
	noEvidenceRef    string
	unclassified     string

	factsTitle      string
	factsEmpty      string
	unverifiedTitle string
	unverifiedEmpty string
	unverifiedNote  string

	reproTitle   string
	scopeLine    string // %1$s task id, %2$d exploration id
	evidenceLine string
}

var enBundle = bundle{
	titlePrefix:      "Penetration Test Report: ",
	unnamedTask:      "Unnamed task",
	goalLabel:        "Task goal",
	goalUnset:        "(not set)",
	taskIDLabel:      "Task ID",
	explorationLabel: "exploration",
	statusLabel:      "Status",
	createdLabel:     "Created",
	completedLabel:   "Completed",
	generatedLabel:   "Generated at",

	summaryTitle:          "Summary",
	confirmedFindingsFmt:  "Confirmed findings: **%d**",
	observedFacts:         "Observed facts",
	unverifiedConclusions: "Unverified conclusions",
	taskAssetsPrefix:      "Task assets (this task's own assets only)",
	taskAssetsEmpty:       "none recorded",
	inheritedNote:         "This task inherited context from task(s) %s; their results are reported in their own reports.",

	findingsTitle: "Confirmed vulnerabilities",
	noFindingsHonest: "No confirmed vulnerabilities were recorded for this task. This reflects only the checks " +
		"actually performed (see the sections below) and is not proof that the targets are secure.",
	evidenceRefFmt: "Evidence reference: finding #%d · status %s · traffic evidence bindings: %d",
	noEvidenceRef:  "Evidence reference: none (no findings-table record links this node; check the findings page)",
	unclassified:   "Unclassified",

	factsTitle:      "Observed facts",
	factsEmpty:      "No observed facts were recorded.",
	unverifiedTitle: "Unverified conclusions",
	unverifiedEmpty: "No inferred conclusions were recorded.",
	unverifiedNote:  "(inferred — not independently verified)",

	reproTitle: "Reproducibility and scope",
	scopeLine:  "This report is generated only from task %s (exploration #%d) data: its own assets, facts and findings. Data of other tasks and projects is not included.",
	evidenceLine: "Evidence is referenced by id (finding #id, traffic bindings, node #id) rather than inlined: full request/response snapshots live in the findings page and the evidence store. " +
		"Raw secrets are intentionally not pasted into this report.",
}

var ruBundle = bundle{
	titlePrefix:      "Отчёт о тестировании на проникновение: ",
	unnamedTask:      "Задача без названия",
	goalLabel:        "Цель задачи",
	goalUnset:        "(не задана)",
	taskIDLabel:      "ID задачи",
	explorationLabel: "исследование",
	statusLabel:      "Статус",
	createdLabel:     "Создана",
	completedLabel:   "Завершена",
	generatedLabel:   "Время формирования",

	summaryTitle:          "Сводка",
	confirmedFindingsFmt:  "Подтверждённых уязвимостей: **%d**",
	observedFacts:         "Наблюдаемых фактов",
	unverifiedConclusions: "Непроверенных выводов",
	taskAssetsPrefix:      "Активы задачи (только собственные активы этой задачи)",
	taskAssetsEmpty:       "не зафиксировано",
	inheritedNote:         "Эта задача унаследовала контекст задач %s; их результаты приводятся в их собственных отчётах.",

	findingsTitle: "Подтверждённые уязвимости",
	noFindingsHonest: "По этой задаче не зафиксировано подтверждённых уязвимостей. Это отражает только фактически " +
		"выполненные проверки (см. разделы ниже) и не является доказательством защищённости целей.",
	evidenceRefFmt: "Отсылка к доказательству: finding #%d · статус %s · привязок трафика: %d",
	noEvidenceRef:  "Отсылка к доказательству: отсутствует (узел не связан с записью в таблице находок; проверьте страницу находок)",
	unclassified:   "Без класса",

	factsTitle:      "Наблюдаемые факты",
	factsEmpty:      "Наблюдаемые факты не зафиксированы.",
	unverifiedTitle: "Непроверенные выводы",
	unverifiedEmpty: "Логические выводы не зафиксированы.",
	unverifiedNote:  "(вывод — независимо не проверено)",

	reproTitle: "Воспроизводимость и охват",
	scopeLine:  "Отчёт сформирован только из данных задачи %s (исследование #%d): её собственных активов, фактов и находок. Данные других задач и проектов не включаются.",
	evidenceLine: "Доказательства приводятся как ссылки (finding #id, привязки трафика, node #id), а не сырыми дампами: полные снимки запросов и ответов находятся на странице находок и в хранилище доказательств. " +
		"Сырые секреты в текст отчёта сознательно не вставляются.",
}

// findingsBundle holds every user-facing skeleton string of the findings-page
// export renderers (findings.go): the multi-finding summary Markdown, the
// single-finding Markdown, the traffic-evidence section and the CSV header.
// Same rules as bundle: fixed wording, format verbs only, never reordered
// placeholders.
type findingsBundle struct {
	summaryReportTitle string // "# <title>"
	generatedLabel     string // "- **<label>**: <time>"
	totalFmt           string // %d = finding count
	summaryTitle       string
	severityCol        string
	countCol           string
	sevCritical        string
	sevHigh            string
	sevMedium          string
	sevLow             string
	emptyLine          string // shown when the filter matches nothing
	detailsTitle       string
	typeLabel          string
	statusLabel        string
	severityLabel      string // single-finding "- **<label>**"
	taskLabel          string
	foundAtLabel       string
	evidenceLabel      string // "**<label>:**"
	reportLabel        string // "**<label>:**" (multi-finding)
	overviewTitle      string // "## <title>"
	evidenceTitle      string // "## <title>"
	reportTitle        string // "## <title>" (single-finding)
	trafficTitle       string // "## <title>"
	trafficVerFmt      string // %1$d evidence version, %2$d binding count
	trafficStale       string
	trafficEntryFmt    string // %1$d idx, %2$d evidence id, %3$s role, %4$s method, %5$s url, %6$d status
	requestMsg         string
	responseMsg        string
	unclassified       string // fallback finding title
	csvHeader          []string
}

var enFindings = findingsBundle{
	summaryReportTitle: "Findings summary report",
	generatedLabel:     "Generated at",
	totalFmt:           "**Total findings**: %d",
	summaryTitle:       "Summary",
	severityCol:        "Severity",
	countCol:           "Count",
	sevCritical:        "Critical",
	sevHigh:            "High",
	sevMedium:          "Medium",
	sevLow:             "Low",
	emptyLine:          "_No findings match the filter._",
	detailsTitle:       "Finding details",
	typeLabel:          "Type",
	statusLabel:        "Status",
	severityLabel:      "Severity",
	taskLabel:          "Task",
	foundAtLabel:       "Found at",
	evidenceLabel:      "Evidence:",
	reportLabel:        "Detailed report:",
	overviewTitle:      "Overview",
	evidenceTitle:      "Evidence",
	reportTitle:        "Detailed report",
	trafficTitle:       "Related traffic evidence",
	trafficVerFmt:      "Evidence version: %d, bindings: %d.",
	trafficStale:       "Evidence has changed; the detailed report needs to be regenerated.",
	trafficEntryFmt:    "%d. **Evidence #%d · %s**: `%s %s`, status code %d",
	requestMsg:         "Request message",
	responseMsg:        "Response message",
	unclassified:       "Unclassified",
	csvHeader:          []string{"ID", "Name", "Type", "Severity", "Status", "Task", "Found at", "Overview", "Traffic evidence count", "Traffic evidence IDs"},
}

var ruFindings = findingsBundle{
	summaryReportTitle: "Сводный отчёт по находкам",
	generatedLabel:     "Время формирования",
	totalFmt:           "**Всего находок**: %d",
	summaryTitle:       "Сводка",
	severityCol:        "Серьёзность",
	countCol:           "Количество",
	sevCritical:        "Критическая",
	sevHigh:            "Высокая",
	sevMedium:          "Средняя",
	sevLow:             "Низкая",
	emptyLine:          "_Под фильтр не попала ни одна находка._",
	detailsTitle:       "Детали находок",
	typeLabel:          "Тип",
	statusLabel:        "Статус",
	severityLabel:      "Серьёзность",
	taskLabel:          "Задача",
	foundAtLabel:       "Время обнаружения",
	evidenceLabel:      "Доказательство:",
	reportLabel:        "Подробный отчёт:",
	overviewTitle:      "Обзор",
	evidenceTitle:      "Доказательство",
	reportTitle:        "Подробный отчёт",
	trafficTitle:       "Связанные доказательства трафика",
	trafficVerFmt:      "Версия доказательств: %d, привязок: %d.",
	trafficStale:       "Доказательства изменились — подробный отчёт нужно переформировать.",
	trafficEntryFmt:    "%d. **Доказательство #%d · %s**: `%s %s`, код состояния %d",
	requestMsg:         "Сообщение запроса",
	responseMsg:        "Сообщение ответа",
	unclassified:       "Без класса",
	csvHeader:          []string{"ID", "Название", "Тип", "Серьёзность", "Статус", "Задача", "Время обнаружения", "Обзор", "Кол-во доказательств трафика", "ID доказательств трафика"},
}

var koFindings = findingsBundle{
	summaryReportTitle: "취약점 요약 보고서",
	generatedLabel:     "생성 시각",
	totalFmt:           "**취약점 총계**: %d건",
	summaryTitle:       "요약",
	severityCol:        "심각도",
	countCol:           "개수",
	sevCritical:        "심각",
	sevHigh:            "높음",
	sevMedium:          "중간",
	sevLow:             "낮음",
	emptyLine:          "_일치하는 취약점이 없습니다._",
	detailsTitle:       "취약점 상세",
	typeLabel:          "유형",
	statusLabel:        "상태",
	severityLabel:      "심각도",
	taskLabel:          "소속 작업",
	foundAtLabel:       "발견 시각",
	evidenceLabel:      "증거:",
	reportLabel:        "상세 보고서:",
	overviewTitle:      "개요",
	evidenceTitle:      "증거",
	reportTitle:        "상세 보고서",
	trafficTitle:       "관련 트래픽 증거",
	trafficVerFmt:      "증거 버전: %d, 바인딩 개수: %d.",
	trafficStale:       "증거가 변경되어 상세 보고서를 갱신해야 합니다.",
	trafficEntryFmt:    "%d. **증거 #%d · %s**: `%s %s`, 상태 코드 %d",
	requestMsg:         "요청 메시지",
	responseMsg:        "응답 메시지",
	unclassified:       "미분류",
	csvHeader:          []string{"ID", "이름", "유형", "심각도", "상태", "소속 작업", "발견 시각", "개요", "트래픽 증거 개수", "트래픽 증거 ID"},
}

// findingsBundleFor resolves the findings-export skeleton language with the
// same rules as bundleFor: en/ru/ko supported, everything else (including "")
// falls back to English.
func findingsBundleFor(locale string) findingsBundle {
	switch strings.ToLower(strings.TrimSpace(locale)) {
	case "ru":
		return ruFindings
	case "ko":
		return koFindings
	default:
		return enFindings
	}
}

var koBundle = bundle{
	titlePrefix:      "침투 테스트 보고서: ",
	unnamedTask:      "이름 없는 작업",
	goalLabel:        "작업 목표",
	goalUnset:        "(지정되지 않음)",
	taskIDLabel:      "작업 ID",
	explorationLabel: "탐색",
	statusLabel:      "상태",
	createdLabel:     "생성",
	completedLabel:   "완료 시각",
	generatedLabel:   "생성 시각",

	summaryTitle:          "요약",
	confirmedFindingsFmt:  "확인된 취약점: **%d**건",
	observedFacts:         "관찰된 사실",
	unverifiedConclusions: "미검증 결론",
	taskAssetsPrefix:      "작업 자산(이 작업 소유 자산만)",
	taskAssetsEmpty:       "기록 없음",
	inheritedNote:         "이 작업은 작업 %s 의 맥락을 이어받았습니다. 해당 작업의 결과는 각자의 보고서에 있습니다.",

	findingsTitle: "확인된 취약점",
	noFindingsHonest: "이번 작업에서 확정된 취약점은 기록되지 않았습니다. 이는 실제로 수행된 점검(아래 섹션 참조)만을 " +
		"반영하며, 대상이 안전하다는 증거가 아닙니다.",
	evidenceRefFmt: "증거 참조: finding #%d · 상태 %s · 트래픽 증거 %d건",
	noEvidenceRef:  "증거 참조: 없음(이 노드에 연결된 finding 레코드가 없음; findings 페이지에서 확인)",
	unclassified:   "미분류",

	factsTitle:      "관찰된 사실",
	factsEmpty:      "기록된 관찰 사실이 없습니다.",
	unverifiedTitle: "미검증 결론",
	unverifiedEmpty: "기록된 추론이 없습니다.",
	unverifiedNote:  "(추론 기반 — 별도 검증 필요)",

	reproTitle: "재현 가능성과 범위",
	scopeLine:  "이 보고서는 작업 %s(탐색 #%d)의 데이터만으로 생성되었습니다: 해당 작업 소유의 자산·사실·취약점만 포함합니다.",
	evidenceLine: "증거는 원본 덤프 대신 참조(finding #id, 트래픽 증거, node #id)로 제공됩니다. 전체 요청/응답 스냅샷은 findings 페이지와 증거 저장소에 있으며, " +
		"원본 시크릿은 보고서 본문에 넣지 않습니다.",
}

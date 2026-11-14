package report

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

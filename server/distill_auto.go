package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// distill_auto.go — терминальный автодистилл задач: после done/timeout собирает
// сводку задачи (находки name/severity/summary + счётчики интентов по состояниям
// + число фактов), одним LLM-выстрелом СТРОГО по образцу insights.go (та же
// insightsCompletion: temp 0, MaxTokens 4000, поле Thinking не выставляется,
// стрим; пустой ответ → 1 ретрай; nil-провайдер → graceful пропуск) извлекает
// кандидатов на навыки и складывает их В ОЧЕРЕДЬ ФАЙЛОВ m.dir/distill/queue/ —
// файл task-<taskID>-<unix>.md (yaml-подобный машиночитаемый блок + человекочитаемое
// тело) + строка в manifest.jsonl.
//
// строго queue-only: никаких мутаций скиллов и никаких PUT — решение о применении
// кандидатов остаётся за человеком, очередь переживает рестарт сервиса (файлы, не
// память процесса). Выключатель — настройка auto_distill ("0"/"off" = выкл,
// дефолт вкл). Хук вызывается из терминальных путей рядом с
// generateTerminalInsights (engine.go planner-met и engine_timeout.go settleTask),
// асинхронно: settle/терминал задачи не блокируется.

const (
	// settingAutoDistill — выключатель терминального автодистилла. Дефолт ВКЛ
	// (пусто/нет ключа); "0"/"off"/"false" выключают. Читается на каждый выстрел,
	// смена применяется со следующей терминальной задачи.
	settingAutoDistill = "auto_distill"
	// distillWorkerLane — отдельный lane в llm_usage-леджере (как "insights" у
	// сводки и "judge" у intercept), чтобы расход на дистилл был виден отдельно.
	distillWorkerLane = "distill"
	// distillGenerateTimeout — бюджет фонового хука (как insightsGenerateTimeout).
	distillGenerateTimeout = 60 * time.Second
	// distillFindingsLimit — сколько находок задачи уходит в контекст промпта.
	distillFindingsLimit = 50
)

// distillActivitySummaryFmt — текст activity в задаче (worker=system, kind=text);
// формат-аргумент — число кандидатов.
const distillActivitySummaryFmt = "дистилл: %d кандидатов в очередь"

const distillSystemPrompt = `Ты — помощник пентест-оркестратора. Задача завершена: извлеки из её итогов повторяемые приёмы, достойные навыка (skill).
На вход даётся компактный JSON контекста задачи: цель (goal), находки (findings), счётчики интентов по состояниям (intents: done/exhausted/blocked/...) и число фактов (facts).
Ответ — СТРОГО JSON вида {"candidates":[{"skill":string,"kind":"new"|"refine","trigger":string,"lesson":string}]}: 1-5 кандидатов, не больше.
skill — короткое имя навыка (slug, латиница); kind — "new" (новый навык) или "refine" (уточнить существующий); trigger — когда применять приём; lesson — конкретный технический вывод этой задачи. Язык значений — русский. Без markdown-разметки и без текста вне JSON.`

// distillCandidate — один кандидат очереди (контракт из ответа модели).
type distillCandidate struct {
	Skill   string `json:"skill"`
	Kind    string `json:"kind"` // "new" | "refine"
	Trigger string `json:"trigger"`
	Lesson  string `json:"lesson"`
}

// distillFinding — находка в контексте промпта (name/severity/summary).
type distillFinding struct {
	Name     string `json:"name"`
	Severity string `json:"severity,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// distillContext — компактный JSON для промпта.
type distillContext struct {
	TaskID   int64            `json:"task_id"`
	Status   string           `json:"status"`
	Goal     string           `json:"goal,omitempty"`
	Findings []distillFinding `json:"findings"`
	Intents  map[string]int   `json:"intents"` // done/exhausted/blocked/...
	Facts    int              `json:"facts"`
}

// ---- устойчивый парсер ответа модели (по образцу parseInsightSuggestions) ----

// parseDistillCandidates достаёт {"candidates":[...]} из сырого ответа модели:
// срезает markdown-фенсы, берёт фрагмент от первой '{' до последней '}'. Кандидаты
// с пустым skill или посторонним kind отбрасываются; битый JSON → пустой список и
// ошибка (выстрел просто не попадёт в очередь).
func parseDistillCandidates(text string) ([]distillCandidate, error) {
	s := strings.TrimSpace(text)
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			s = s[nl+1:]
		}
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "```"))
	}
	if i := strings.IndexByte(s, '{'); i >= 0 {
		if j := strings.LastIndexByte(s, '}'); j > i {
			s = s[i : j+1]
		}
	}
	var out struct {
		Candidates []distillCandidate `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []distillCandidate{}, fmt.Errorf("не удалось разобрать ответ модели: %v", err)
	}
	cands := make([]distillCandidate, 0, len(out.Candidates))
	for _, c := range out.Candidates {
		c.Skill = strings.TrimSpace(c.Skill)
		c.Kind = strings.TrimSpace(c.Kind)
		c.Trigger = strings.TrimSpace(c.Trigger)
		c.Lesson = strings.TrimSpace(c.Lesson)
		if c.Skill == "" || (c.Kind != "new" && c.Kind != "refine") {
			continue
		}
		cands = append(cands, c)
	}
	return cands, nil
}

// ---- очередь-каталог (m.dir/distill/queue) ----

// distillQueueFileName — имя файла очереди: task-<taskID>-<unix-секунды>.md.
func distillQueueFileName(taskID string, at time.Time) string {
	return fmt.Sprintf("task-%s-%d.md", taskID, at.Unix())
}

// renderDistillQueueFile — содержимое файла очереди: yaml-подобный
// машиночитаемый блок между '---' (task_id/status/created_at/candidates) +
// человекочитаемое тело с кандидатами.
func renderDistillQueueFile(taskID, status string, at time.Time, cands []distillCandidate) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "task_id: %s\n", taskID)
	fmt.Fprintf(&b, "status: %s\n", status)
	fmt.Fprintf(&b, "created_at: %s\n", rfc3339(at))
	fmt.Fprintf(&b, "candidates: %d\n", len(cands))
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "# Дистилл задачи %s (%s)\n\n", taskID, status)
	for i, c := range cands {
		fmt.Fprintf(&b, "## %d. %s — %s\n\n", i+1, c.Skill, c.Kind)
		if c.Trigger != "" {
			fmt.Fprintf(&b, "- trigger: %s\n", c.Trigger)
		}
		if c.Lesson != "" {
			fmt.Fprintf(&b, "- lesson: %s\n", c.Lesson)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// writeDistillQueue кладёт файл очереди в dir/distill/queue/ и добавляет строку в
// manifest.jsonl (append; одна строка JSON = один файл). Возвращает имя файла.
// Никаких мутаций скиллов — только файлы.
func writeDistillQueue(dir, taskID, status string, at time.Time, cands []distillCandidate) (string, error) {
	qdir := filepath.Join(dir, "distill", "queue")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return "", err
	}
	name := distillQueueFileName(taskID, at)
	if err := os.WriteFile(filepath.Join(qdir, name), []byte(renderDistillQueueFile(taskID, status, at, cands)), 0o600); err != nil {
		return "", err
	}
	line, err := json.Marshal(map[string]any{
		"file":       name,
		"task_id":    taskID,
		"status":     status,
		"candidates": len(cands),
		"created_at": rfc3339(at),
	})
	if err != nil {
		return name, err
	}
	mf, err := os.OpenFile(filepath.Join(qdir, "manifest.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return name, err
	}
	defer mf.Close()
	if _, err := mf.Write(append(line, '\n')); err != nil {
		return name, err
	}
	return name, nil
}

// ---- детерминированная база (без LLM) ----

// buildDistillContext собирает findings (name/severity/summary из узлов задачи),
// счётчики интентов по состояниям (IntentStateCounts: done/exhausted/blocked/...)
// и число фактов. Ошибка отдельного источника не прерывает сборку — что собрали,
// то в контексте; все ошибки вернутся одной (errors.Join), как в
// buildInsightsContext.
func buildDistillContext(t *Task, status string) (*distillContext, error) {
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	base := &distillContext{TaskID: taskID, Status: status, Goal: t.Goal,
		Findings: []distillFinding{}, Intents: map[string]int{}}
	var errs []error
	if nodes, err := t.Store.ListByKind(db.KindFinding, distillFindingsLimit); err != nil {
		errs = append(errs, err)
	} else {
		for _, n := range nodes {
			var p struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
				Summary  string `json:"summary"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			base.Findings = append(base.Findings, distillFinding{Name: p.Name, Severity: p.Severity, Summary: p.Summary})
		}
	}
	if counts, err := t.Store.IntentStateCounts(); err != nil {
		errs = append(errs, err)
	} else {
		base.Intents = counts
	}
	if n, err := t.Store.CountByKind(db.KindFact); err != nil {
		errs = append(errs, err)
	} else {
		base.Facts = n
	}
	return base, errors.Join(errs...)
}

// ---- выключатель ----

// autoDistillEnabled читает auto_distill: дефолт ВКЛ (нет ключа/пусто/ошибка
// чтения — паттерн TaskDefaultTimeout); "0"/"off"/"false" выключают. Движок без
// БД (тестовые контексты) дистилл не запускает.
func (e *Engine) autoDistillEnabled() bool {
	if e.m == nil || e.m.pg == nil {
		return false
	}
	v, ok, err := e.m.pg.GetSetting(settingAutoDistill)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false":
		return false
	}
	return true
}

// ---- терминальный хук (рядом с generateTerminalInsights) ----

// autoDistillTerminal — терминальный хук (planner-met / settleTask): фоновая
// горутина + defer recover + собственный 60s-контекст, точный образец
// generateTerminalInsights (insights.go) — терминал/settle задачи не блокируется.
func (e *Engine) autoDistillTerminal(t *Task, status string) {
	if t == nil {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[distill] task %s автодистилл упал (recover): %v", t.ID, rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), distillGenerateTimeout)
		defer cancel()
		e.runAutoDistill(ctx, t, status)
	}()
}

// runAutoDistill — ядро: дедуп терминала (distillDone; revival задачи сбрасывает
// флаг) → выключатель auto_distill → провайдер без *Server (insightsOneShotProvider;
// nil → graceful пропуск, файлы не пишутся) → контекст → one-shot LLM через
// insightsCompletion (temp 0, MaxTokens 4000, Thinking не выставляется, стрим;
// пустой ответ → 1 ретрай) → парс → файл очереди + manifest → activity в задачу.
func (e *Engine) runAutoDistill(ctx context.Context, t *Task, status string) {
	// Дедуп двойного выстрела (timeout-путь + planner-met): терминал задачи
	// дистиллируется один раз; повторная постановка в running сбрасывает флаг.
	if _, loaded := e.distillDone.LoadOrStore(t.ID, true); loaded {
		return
	}
	if !e.autoDistillEnabled() {
		return
	}
	if t.Store == nil {
		return // задачи без exploration-хранилища дистиллить нечего
	}
	// Провайдер строится без *Server (как у терминальных инсайтов): профиль
	// задачи → закреплённый → глобальный активный; битый/без ключа → nil →
	// graceful-пропуск без ошибок. Пропуск по ВРЕМЕННОЙ причине снимает флаг
	// дедупа: парный триггер (timeout-путь/planner-met) или revival сможет
	// дистиллировать позже; структурные пропуски (выключатель, пустая задача)
	// флаг оставляют — повторять их бессмысленно.
	var prov llm.Provider
	if profileID := insightsProfileID(e.m, t); profileID != 0 {
		prov = insightsOneShotProvider(e.m, profileID)
	}
	if prov == nil {
		log.Printf("[distill] task %s пропущен: LLM-профиль не настроен", t.ID)
		e.distillDone.Delete(t.ID)
		return
	}
	base, err := buildDistillContext(t, status)
	if err != nil {
		// Частичная база тоже годится в промпт — что собрали, то уйдёт; но совсем
		// пустую задачу (нет находок и интентов) дистиллить нечем.
		log.Printf("[distill] task %s сборка контекста (частично): %v", t.ID, err)
	}
	if len(base.Findings) == 0 && len(base.Intents) == 0 {
		log.Printf("[distill] task %s пропущен: ни находок, ни интентов", t.ID)
		return
	}
	user, err := json.Marshal(base)
	if err != nil {
		log.Printf("[distill] task %s сериализация контекста: %v", t.ID, err)
		return
	}
	// Расход — в отдельный lane "distill" (как "insights" у сводки).
	llmCtx := llmrec.WithWorker(ctx, distillWorkerLane)
	text, err := insightsCompletion(llmCtx, prov, distillSystemPrompt, string(user))
	if err == nil && strings.TrimSpace(text) == "" {
		// thinking-модель иногда отдаёт пустой content: один ретрай
		text, err = insightsCompletion(llmCtx, prov, distillSystemPrompt, string(user))
	}
	if err != nil {
		log.Printf("[distill] task %s LLM-вызов: %v", t.ID, err)
		e.distillDone.Delete(t.ID) // временный сбой — разрешить повтор
		return
	}
	cands, err := parseDistillCandidates(text)
	if err != nil {
		log.Printf("[distill] task %s %v", t.ID, err)
		e.distillDone.Delete(t.ID) // временный сбой — разрешить повтор
		return
	}
	if len(cands) == 0 {
		log.Printf("[distill] task %s: пустой список кандидатов", t.ID)
		return
	}
	name, err := writeDistillQueue(e.m.dir, t.ID, status, time.Now(), cands)
	if err != nil {
		log.Printf("[distill] task %s запись очереди: %v", t.ID, err)
		e.distillDone.Delete(t.ID) // временный сбой — разрешить повтор
		return
	}
	log.Printf("[distill] task %s: %d кандидатов в очередь (%s)", t.ID, len(cands), name)
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf(distillActivitySummaryFmt, len(cands))})
}

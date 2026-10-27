package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// insights.go — AI-сводка «что дальше / не прошлись» (E-BACK ч.2):
//
//	GET /api/tasks/{id}/insights — детерминированная база (coverage/untested/goals/
//	findings) + однократный LLM-свод из 5-8 шагов; 60s кэш готового ответа. LLM нет
//	или ошибка → HTTP 200 с пустыми suggestions и причиной в error, чтобы UI не
//	ломался. Терминальные пути (settleTask / planner-met) зовут ту же генерацию
//	фоном и пишут одну activity (kind=insights), не блокируя settle.

// insightsWorkerLane is the usage-ledger lane for insights LLM calls (like the
// intercept judge's "judge" lane), so this spend is queryable apart from the
// worker/planner/main lanes.
const insightsWorkerLane = "insights"

const (
	insightsCacheTTL        = 60 * time.Second // готовый ответ живёт минуту: двойной выстрел терминала не дублирует LLM-вызов
	insightsGenerateTimeout = 60 * time.Second // бюджет и фонового хука, и HTTP-запроса
	insightsMaxTokens       = 1200
	insightsUntestedLimit   = 10
)

// Пользователю видны только error и activity-сводка; язык — русский, как у промпта.
const (
	errInsightsNoLLM        = "LLM-профиль не настроен — сводка недоступна"
	errInsightsBadJSONFmt   = "не удалось разобрать ответ модели: %v"
	insightsActivitySummary = "Инсайты: что ещё можно попробовать"
)

const insightsSystemPrompt = `Ты — помощник пентест-оркестратора. Задача уже завершена: подведи итог и предложи, что проверить дальше.
На вход даётся компактный JSON контекста задачи: покрытие активов (coverage), непроверенные активы (untested), открытые цели (open_goals), подтверждённые находки (findings).
Ответ — СТРОГО JSON вида {"suggestions": ["...", ...]}: 5-8 конкретных технических шагов «что ещё можно попробовать» по этой задаче (какие активы и вектора проверить, какие находки углубить). Язык — русский. Без markdown-разметки и без текста вне JSON.`

// ---- ответ эндпоинта ----

type insightsCoverage struct {
	Enabled bool     `json:"enabled"`
	Pct     *float64 `json:"pct"` // 0..1, в том же масштабе, что coverage-эндпоинт; null = нет данных
}

type insightsResponse struct {
	TaskID      int64              `json:"task_id"`
	Status      string             `json:"status"`
	Coverage    insightsCoverage   `json:"coverage"`
	Untested    []db.CoverageAsset `json:"untested"`
	Suggestions []string           `json:"suggestions"`
	GeneratedAt string             `json:"generated_at"`
	Error       string             `json:"error,omitempty"`
}

// ---- детерминированная база (без LLM) ----

type insightsGoal struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

type insightsFinding struct {
	VulnClass string `json:"vulnclass,omitempty"`
	Name      string `json:"name,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Summary   string `json:"summary,omitempty"`
	State     string `json:"state,omitempty"`
}

// insightsContext — компактный JSON для промпта (и источник полей ответа).
type insightsContext struct {
	TaskID        int64              `json:"task_id"`
	Goal          string             `json:"goal,omitempty"`
	Status        string             `json:"status"`
	Coverage      insightsCoverage   `json:"coverage"`
	Untested      []db.CoverageAsset `json:"untested"`
	UntestedTotal int                `json:"untested_total"`
	OpenGoals     []insightsGoal     `json:"open_goals"`
	Findings      []insightsFinding  `json:"findings"`
}

// buildInsightsContext собирает LLM-свободную базу: покрытие и непроверенные активы
// (обе query учитывают прямые source-задачи), открытые цели, находки. Ошибка
// отдельного источника не прерывает сборку — что собрали, то в контексте; все
// ошибки вернутся одной (errors.Join) и попадут в error ответа.
func buildInsightsContext(m *Manager, t *Task, status string) (*insightsContext, error) {
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	base := &insightsContext{
		TaskID: taskID, Goal: t.Goal, Status: status,
		Coverage:  insightsCoverage{Enabled: t.CoverageEnabled},
		Untested:  []db.CoverageAsset{},
		OpenGoals: []insightsGoal{},
		Findings:  []insightsFinding{},
	}
	var errs []error
	if as := m.Assets(); as != nil && t.CoverageEnabled {
		if cov, err := as.TaskCoverageWithSources(taskID); err != nil {
			errs = append(errs, err)
		} else if cov != nil {
			base.Coverage.Pct = cov.Pct
		}
		untested, total, err := as.ListUntestedAssetsWithSources(taskID, "", insightsUntestedLimit, 0)
		if err != nil {
			errs = append(errs, err)
		} else {
			base.Untested, base.UntestedTotal = untested, total
		}
	}
	if goals, err := t.Store.ListByKind(db.KindGoal, 1000); err != nil {
		errs = append(errs, err)
	} else {
		for _, n := range goals {
			if n.State != "open" {
				continue
			}
			var p struct {
				Text      string `json:"text"`
				VulnClass string `json:"vulnclass"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			if strings.TrimSpace(p.Text) == "" {
				continue
			}
			base.OpenGoals = append(base.OpenGoals, insightsGoal{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	if findings, err := t.Store.ListByKind(db.KindFinding, 50); err != nil {
		errs = append(errs, err)
	} else {
		for _, n := range findings {
			var p struct {
				VulnClass string `json:"vulnclass"`
				Name      string `json:"name"`
				Severity  string `json:"severity"`
				Summary   string `json:"summary"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			base.Findings = append(base.Findings, insightsFinding{
				VulnClass: p.VulnClass, Name: p.Name, Severity: p.Severity, Summary: p.Summary, State: n.State,
			})
		}
	}
	return base, errors.Join(errs...)
}

// ---- устойчивый парсер ответа модели ----

// parseInsightSuggestions достаёт {"suggestions":[...]} из сырого ответа модели:
// срезает markdown-фенсы, берёт фрагмент от первой '{' до последней '}'. Не
// распарсилось → пустой список и причина (эндпоинт вернёт suggestions:[] + error).
func parseInsightSuggestions(text string) ([]string, error) {
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
		Suggestions []string `json:"suggestions"`
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []string{}, fmt.Errorf(errInsightsBadJSONFmt, err)
	}
	suggestions := make([]string, 0, len(out.Suggestions))
	for _, item := range out.Suggestions {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			suggestions = append(suggestions, trimmed)
		}
	}
	return suggestions, nil
}

// ---- однократный LLM-вызов (по образцу streamCollectText, MaxTokens 1200) ----

func insightsCompletion(ctx context.Context, prov llm.Provider, system, user string) (string, error) {
	temp := 0.0
	req := llm.CompletionRequest{
		System:      []string{system},
		Messages:    []llm.Message{llm.UserText(user)},
		MaxTokens:   insightsMaxTokens,
		Temperature: &temp,
		Thinking:    "disabled",
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String(), nil
}

// ---- выбор профиля и провайдера ----

// insightsProfileID решает, на каком профиле делать свод: активный профиль задачи
// (runtime pin), иначе закреплённый, иначе глобальный активный. 0 = профиля нет.
func insightsProfileID(m *Manager, t *Task) int64 {
	st := t.llmStateSnapshot()
	if st.ActiveID != nil {
		return *st.ActiveID
	}
	if st.ProfileID != nil {
		return *st.ProfileID
	}
	if m != nil && m.pg != nil {
		if p, err := m.pg.ActiveProfile(); err == nil && p != nil {
			return p.ID
		}
	}
	return 0
}

// insightsOneShotProvider строит провайдер для одного вызова без *Server (путь
// engine-хука: кэш providerForProfile недоступен). Профиль битый/без ключа → nil →
// graceful-пусто. Расход уходит в леджер через llmrec.Wrap, как у остальных.
func insightsOneShotProvider(m *Manager, profileID int64) llm.Provider {
	if m == nil || m.pg == nil || profileID == 0 {
		return nil
	}
	p, err := m.pg.ProfileByID(profileID)
	if err != nil || p == nil || p.APIKey == "" {
		return nil
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ContextWindowK = p.ContextWindowK
	cfg.ThinkingType, cfg.ReasoningEffort = p.ThinkingType, p.ReasoningEffort
	cfg.Stream = p.Streaming
	cfg.MaxTokens, cfg.MaxTokensField = p.MaxTokens, p.MaxTokensField
	prov, err := cfg.NewProvider()
	if err != nil {
		return nil
	}
	return llmrec.Wrap(prov, m.PG(), cfg.Model, p.Name, cfg.ThinkingType, cfg.ReasoningEffort, m.LLMRecordEnabled)
}

// ---- кэш готовых ответов (на Engine: см. fields в engine.go) ----

type insightsCacheEntry struct {
	resp *insightsResponse
	at   time.Time
}

func (e *Engine) insightsCached(taskID int64) (*insightsResponse, bool) {
	e.insightsMu.Lock()
	defer e.insightsMu.Unlock()
	entry, ok := e.insightsCache[taskID]
	if !ok || time.Since(entry.at) >= insightsCacheTTL {
		return nil, false
	}
	return entry.resp, true
}

func (e *Engine) insightsStoreCache(taskID int64, resp *insightsResponse) {
	e.insightsMu.Lock()
	if e.insightsCache == nil {
		e.insightsCache = map[int64]insightsCacheEntry{}
	}
	e.insightsCache[taskID] = insightsCacheEntry{resp: resp, at: time.Now()}
	e.insightsMu.Unlock()
}

// ---- ядро генерации (общее для HTTP и терминального хука) ----

// generateInsights строит ответ эндпоинта: свежий (<TTL) кэш → сразу из него,
// иначе детерминированная база + LLM-свод. fromCache=true значит, что параллельный
// путь только что сгенерировал копию — терминальный хук в этом случае не пишет
// вторую activity. resolve подключает серверный кэш провайдеров
// (providerForProfile); nil (engine-путь) → однократный провайдер.
func generateInsights(ctx context.Context, e *Engine, t *Task, status string, resolve func(int64) (llm.Provider, bool)) (*insightsResponse, bool, error) {
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if resp, ok := e.insightsCached(taskID); ok {
		return resp, true, nil
	}
	resp := &insightsResponse{TaskID: taskID, Status: status, Suggestions: []string{}, GeneratedAt: rfc3339(time.Now())}
	store := func() { e.insightsStoreCache(taskID, resp) }
	// база возвращается и при частичной ошибке — что собрали, то уйдёт в ответ
	base, err := buildInsightsContext(e.m, t, status)
	resp.Coverage, resp.Untested = base.Coverage, base.Untested
	if err != nil {
		resp.Error = err.Error()
		store()
		return resp, false, err
	}

	var prov llm.Provider
	if profileID := insightsProfileID(e.m, t); profileID != 0 {
		if resolve != nil {
			prov, _ = resolve(profileID)
		}
		if prov == nil {
			prov = insightsOneShotProvider(e.m, profileID)
		}
	}
	if prov == nil {
		resp.Error = errInsightsNoLLM
		store()
		return resp, false, errors.New(errInsightsNoLLM)
	}
	user, err := json.Marshal(base)
	if err != nil {
		resp.Error = err.Error()
		store()
		return resp, false, err
	}
	// Расход — в отдельный lane "insights", чтобы страница конфигурации видела его
	// отдельно от worker/planner (как judge-расход у intercept).
	llmCtx := llmrec.WithWorker(ctx, insightsWorkerLane)
	text, err := insightsCompletion(llmCtx, prov, insightsSystemPrompt, string(user))
	if err != nil {
		resp.Error = err.Error()
		store()
		return resp, false, err
	}
	suggestions, err := parseInsightSuggestions(text)
	if err != nil {
		resp.Error = err.Error()
		store()
		return resp, false, err
	}
	resp.Suggestions = suggestions
	store()
	return resp, false, nil
}

// ---- HTTP handler ----

// insightsProfileProvider адаптирует серверный кэш провайдеров под ядро генерации.
func (s *Server) insightsProfileProvider(id int64) (llm.Provider, bool) {
	prov, _, ok := s.providerForProfile(id)
	return prov, ok
}

// taskInsights — GET /api/tasks/{id}/insights. Любая деградация (нет LLM, битый
// JSON, ошибка сборки) остаётся HTTP 200 с suggestions:[] и причиной в error;
// 404 только когда задачи нет.
func (s *Server) taskInsights(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), insightsGenerateTimeout)
	defer cancel()
	resp, _, _ := generateInsights(ctx, s.engine, t, s.resolvedTaskStatus(t), s.insightsProfileProvider)
	writeJSON(w, 200, resp)
}

// ---- терминальный хук (settleTask / planner-met) ----

// generateTerminalInsights фоном генерирует инсайты завершившейся задачи и пишет
// одну activity (worker=system, kind=insights; Detail — JSON ответа). settle не
// блокируется: свой 60s-контекст, defer-recover; свежий кэш → вторую activity не
// плодим (двойной выстрел timeout-путь + planner-met). Без содержательных
// suggestions (нет LLM/ошибка) activity не пишем — только лог.
func (e *Engine) generateTerminalInsights(t *Task, status string) {
	if t == nil {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[insights] task %s автогенерация упала (recover): %v", t.ID, rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), insightsGenerateTimeout)
		defer cancel()
		resp, fromCache, err := generateInsights(ctx, e, t, status, nil)
		if fromCache {
			return
		}
		if err != nil || len(resp.Suggestions) == 0 {
			log.Printf("[insights] task %s сводка не построена: %v", t.ID, err)
			return
		}
		detail, err := json.Marshal(resp)
		if err != nil {
			log.Printf("[insights] task %s сериализация ответа: %v", t.ID, err)
			return
		}
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "insights",
			Summary: insightsActivitySummary, Detail: string(detail)})
	}()
}

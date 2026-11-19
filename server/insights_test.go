package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// insightsServer — тестовый харнесс инсайтов: менеджер на локальном postgres
// (нет postgres → skip), сервер с погашенным ctx (фоновые циклы не бегут) и
// JWT-запросник. Таблица LLM-профилей чистится, чтобы генерация гарантированно
// шла по graceful-ветке «нет LLM» — живых LLM-вызовов в тестах нет.
func insightsServer(t *testing.T) (*Server, *Manager, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	// Соседние тесты на общей БД могли оставить профили; активный снять флагом.
	for _, p := range mustListProfiles(t, m) {
		if p.IsDefault {
			_, _ = m.pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id=$1`, p.ID)
		}
		_ = m.pg.DeleteProfile(p.ID)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	td := t.TempDir()
	s := New(ctx, m, td, td, td)
	s.archiveWG.Wait()
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	return s, m, request
}

func mustListProfiles(t *testing.T, m *Manager) []*db.LLMProfile {
	t.Helper()
	profiles, err := m.pg.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	return profiles
}

// insightsFixtureTask создаёт задачу с открытой и закрытой целью, одной находкой
// и одним непроверенным активом в scope — детерминированная база инсайтов.
func insightsFixtureTask(t *testing.T, m *Manager) (*Task, int64) {
	t.Helper()
	task, err := m.CreateTask("insights fixture", "проверить веб-входы", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, tid)
		_ = m.pg.DeleteTask(tid)
	})
	if _, err := task.Store.AddGoal(map[string]any{"text": "Проверить админ-панель", "vulnclass": "auth"}, "human"); err != nil {
		t.Fatal(err)
	}
	metID, err := task.Store.AddGoal(map[string]any{"text": "Закрытая цель"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET state='met' WHERE id=$1`, metID); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: tid, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "INSGT", Name: "Insight fixture", Severity: "low", Summary: "тестовая находка",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`INSERT INTO assets(type, domain, root_domain) VALUES('subdomain','un.insights.test','insights.test')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM assets WHERE root_domain='insights.test'`) })
	if _, err := m.pg.Exec(`INSERT INTO task_scope(task_id, kind, domain, source) VALUES($1,'root_domain','insights.test','manual')`, tid); err != nil {
		t.Fatal(err)
	}
	return task, tid
}

// TestBuildInsightsContext проверяет детерминированный сборщик: открытые цели
// (закрытые не считаются), находки, покрытие и untested-отстой по scope.
func TestBuildInsightsContext(t *testing.T) {
	_, m, _ := insightsServer(t)
	task, tid := insightsFixtureTask(t, m)
	base, err := buildInsightsContext(m, task, "done")
	if err != nil {
		t.Fatal(err)
	}
	if base.TaskID != tid || base.Status != "done" || base.Goal != "проверить веб-входы" {
		t.Fatalf("базовые поля: %+v", base)
	}
	if len(base.OpenGoals) != 1 || base.OpenGoals[0].Text != "Проверить админ-панель" || base.OpenGoals[0].VulnClass != "auth" {
		t.Fatalf("открытые цели: %+v", base.OpenGoals)
	}
	if len(base.Findings) != 1 || base.Findings[0].VulnClass != "INSGT" || base.Findings[0].Severity != "low" {
		t.Fatalf("находки: %+v", base.Findings)
	}
	if !base.Coverage.Enabled || base.Coverage.Pct == nil || *base.Coverage.Pct != 0 {
		t.Fatalf("покрытие: %+v", base.Coverage)
	}
	if len(base.Untested) != 1 || base.UntestedTotal != 1 || base.Untested[0].Label != "un.insights.test" {
		t.Fatalf("untested: %+v total=%d", base.Untested, base.UntestedTotal)
	}
}

// TestTaskInsightsEndpoint: 200 со всеми полями; без LLM — graceful suggestions:[]
// и причина в error; 404 на несуществующую задачу; повторный запрос берёт кэш.
func TestTaskInsightsEndpoint(t *testing.T) {
	_, m, request := insightsServer(t)
	task, tid := insightsFixtureTask(t, m)
	r := request("GET", "/api/tasks/"+task.ID+"/insights", "")
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var body struct {
		TaskID      int64              `json:"task_id"`
		Status      string             `json:"status"`
		Coverage    insightsCoverage   `json:"coverage"`
		Untested    []db.CoverageAsset `json:"untested"`
		Suggestions []string           `json:"suggestions"`
		GeneratedAt string             `json:"generated_at"`
		Error       string             `json:"error"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err, r.Body.String())
	}
	if body.TaskID != tid || body.Status == "" || body.GeneratedAt == "" {
		t.Fatalf("поля ответа: %+v", body)
	}
	if body.Coverage.Enabled != task.CoverageEnabled {
		t.Fatalf("coverage.enabled=%v, want %v", body.Coverage.Enabled, task.CoverageEnabled)
	}
	if body.Untested == nil || len(body.Untested) != 1 {
		t.Fatalf("untested должен быть массивом из 1 элемента: %+v", body.Untested)
	}
	if len(body.Suggestions) != 0 || body.Error == "" {
		t.Fatalf("без LLM ожидались пустые suggestions и причина: suggestions=%+v error=%q", body.Suggestions, body.Error)
	}
	// Кэш 60с: второй запрос возвращает ту же копию (тот же generated_at).
	r2 := request("GET", "/api/tasks/"+task.ID+"/insights", "")
	if r2.Code != 200 {
		t.Fatal(r2.Code, r2.Body.String())
	}
	var body2 struct {
		GeneratedAt string `json:"generated_at"`
	}
	if err := json.Unmarshal(r2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if body2.GeneratedAt != body.GeneratedAt {
		t.Fatalf("кэш не сработал: %q vs %q", body2.GeneratedAt, body.GeneratedAt)
	}
	// Несуществующая задача → 404, как у соседних хендлеров.
	if r404 := request("GET", "/api/tasks/99999999/insights", ""); r404.Code != 404 {
		t.Fatal(r404.Code, r404.Body.String())
	}
}

// TestGenerateInsightsUsesCache: первый вызов без LLM даёт graceful-ошибку и
// кладёт ответ в кэш; второй берёт из кэша (fromCache=true) — терминальный хук на
// этом не плодит вторую activity.
func TestGenerateInsightsUsesCache(t *testing.T) {
	s, m, _ := insightsServer(t)
	task, _ := insightsFixtureTask(t, m)
	resp, fromCache, err := generateInsights(context.Background(), s.engine, task, "timeout", nil)
	if fromCache {
		t.Fatal("первый вызов не должен попасть в кэш")
	}
	if err == nil || resp.Error == "" || len(resp.Suggestions) != 0 {
		t.Fatalf("без LLM ожидалась graceful-деградация: err=%v resp=%+v", err, resp)
	}
	cached, fromCache, _ := generateInsights(context.Background(), s.engine, task, "timeout", nil)
	if !fromCache || cached != resp {
		t.Fatalf("второй вызов должен взять кэш: fromCache=%v", fromCache)
	}
}

// TestParseInsightSuggestions: markdown-фенсы, посторонний текст вокруг JSON,
// пустые строки срезаются; мусор → пустой список и ошибка.
func TestParseInsightSuggestions(t *testing.T) {
	fenced := "```json\n{\"suggestions\": [\"Шаг 1\", \"Шаг 2\"]}\n```"
	if got, err := parseInsightSuggestions(fenced); err != nil || len(got) != 2 || got[0] != "Шаг 1" {
		t.Fatalf("фенс: got=%v err=%v", got, err)
	}
	prose := "Вот ответ:\n{\"suggestions\":[\"Проверить X\", \"  \", \"\"]}\nГотово."
	if got, err := parseInsightSuggestions(prose); err != nil || len(got) != 1 || got[0] != "Проверить X" {
		t.Fatalf("текст вокруг JSON: got=%v err=%v", got, err)
	}
	if got, err := parseInsightSuggestions("мусор без JSON"); err == nil || len(got) != 0 {
		t.Fatalf("мусор: got=%v err=%v", got, err)
	}
	if got, err := parseInsightSuggestions(`{"suggestions": []}`); err != nil || len(got) != 0 {
		t.Fatalf("пустой список: got=%v err=%v", got, err)
	}
}

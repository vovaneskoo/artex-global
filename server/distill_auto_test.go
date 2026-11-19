package server

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestParseDistillCandidates — парсер JSON-кандидатов: валидный ответ (в т.ч. в
// markdown-фенсе и с текстом вокруг), фильтрация пустых skill и посторонних kind,
// битый JSON → ошибка + пустой список, пустой список кандидатов — не ошибка.
func TestParseDistillCandidates(t *testing.T) {
	valid := `{"candidates":[
		{"skill":"sqli-auth-bypass","kind":"new","trigger":"логин с SQL-ошибкой","lesson":"union-обход фильтра"},
		{"skill":"  ","kind":"new","trigger":"t","lesson":"l"},
		{"skill":"portscan-fast","kind":"weird","trigger":"t","lesson":"l"},
		{"skill":"xss-dom","kind":"refine","trigger":"SPA-роуты","lesson":"источники в location.hash"}
	]}`
	got, err := parseDistillCandidates(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Skill != "sqli-auth-bypass" || got[0].Kind != "new" ||
		got[1].Skill != "xss-dom" || got[1].Kind != "refine" {
		t.Fatalf("валидный ответ: %+v", got)
	}

	fenced := "```json\n" + valid + "\n```"
	if got, err = parseDistillCandidates(fenced); err != nil || len(got) != 2 {
		t.Fatalf("фенс: got=%v err=%v", got, err)
	}
	prose := "Итог:\n" + valid + "\nГотово."
	if got, err = parseDistillCandidates(prose); err != nil || len(got) != 2 {
		t.Fatalf("текст вокруг JSON: got=%v err=%v", got, err)
	}
	if got, err = parseDistillCandidates("мусор без JSON"); err == nil || len(got) != 0 {
		t.Fatalf("битый: got=%v err=%v", got, err)
	}
	if got, err = parseDistillCandidates(`{"candidates":[]}`); err != nil || len(got) != 0 {
		t.Fatalf("пустой список: got=%v err=%v", got, err)
	}
}

// TestDistillQueueFileName — формат имени файла очереди task-<taskID>-<unix>.md.
func TestDistillQueueFileName(t *testing.T) {
	at := time.Unix(1760000000, 0)
	if got := distillQueueFileName("42", at); got != "task-42-1760000000.md" {
		t.Fatalf("имя файла = %q, want task-42-1760000000.md", got)
	}
	if got := distillQueueFileName("7", at.Add(time.Second)); got != "task-7-1760000001.md" {
		t.Fatalf("имя файла = %q", got)
	}
}

// TestWriteDistillQueueFileAndManifest — запись очереди: файл с yaml-подобным
// блоком и человекочитаемым телом в dir/distill/queue/, по строке JSON на файл в
// manifest.jsonl (append), повторная запись добавляет, а не перезаписывает.
func TestWriteDistillQueueFileAndManifest(t *testing.T) {
	dir := t.TempDir()
	at := time.Unix(1760000000, 0)
	cands := []distillCandidate{
		{Skill: "xss-dom", Kind: "new", Trigger: "SPA-роуты", Lesson: "источники в location.hash"},
		{Skill: "portscan", Kind: "refine", Trigger: "новый сегмент", Lesson: "сначала top-100"},
	}
	name, err := writeDistillQueue(dir, "7", "done", at, cands)
	if err != nil {
		t.Fatal(err)
	}
	if name != "task-7-1760000000.md" {
		t.Fatalf("имя файла = %q", name)
	}
	body, err := os.ReadFile(filepath.Join(dir, "distill", "queue", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{
		"---\n", "task_id: 7\n", "status: done\n", "candidates: 2\n",
		"# Дистилл задачи 7 (done)", "## 1. xss-dom — new", "- trigger: SPA-роуты",
		"## 2. portscan — refine", "- lesson: сначала top-100",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("тело файла не содержит %q:\n%s", want, s)
		}
	}
	if !strings.HasPrefix(s, "---\n") {
		t.Fatalf("yaml-блок должен открывать файл:\n%s", s)
	}

	// manifest.jsonl: строка на файл, append при повторной записи.
	if _, err := writeDistillQueue(dir, "8", "timeout", at.Add(time.Second), cands[:1]); err != nil {
		t.Fatal(err)
	}
	mf, err := os.Open(filepath.Join(dir, "distill", "queue", "manifest.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	var lines []string
	sc := bufio.NewScanner(mf)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("manifest строк = %d, want 2: %v", len(lines), lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["file"] != "task-7-1760000000.md" || first["task_id"] != "7" ||
		first["status"] != "done" || first["candidates"] != float64(2) {
		t.Fatalf("первая строка manifest: %+v", first)
	}
}

// TestAutoDistillNilManagerSkipsGracefully — движок без БД (nil-pg): выключатель и
// провайдер уходят в graceful-пропуск, очередь не пишется, ничего не паникует;
// повторный выстрел по той же задаче съедается дедуп-флагом.
func TestAutoDistillNilManagerSkipsGracefully(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(&Manager{dir: dir})
	e.runAutoDistill(context.Background(), &Task{ID: "1"}, "done") // Store==nil и pg==nil — оба guard'а
	e.runAutoDistill(context.Background(), &Task{ID: "1"}, "done") // дедуп
	if _, err := os.Stat(filepath.Join(dir, "distill")); !os.IsNotExist(err) {
		t.Fatalf("очередь не должна создаваться: %v", err)
	}
}

// TestAutoDistillNilProviderGraceful — живая БД без LLM-профилей: провайдер nil →
// дистилл пропускается без ошибок и файлов, задача не получает activity.
func TestAutoDistillNilProviderGraceful(t *testing.T) {
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
	task, err := m.CreateTask("distill fixture", "проверить входы", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.Store.ID()) })
	e := NewEngine(m)
	e.runAutoDistill(context.Background(), task, "done")
	if entries, err := os.ReadDir(filepath.Join(m.dir, "distill", "queue")); err == nil && len(entries) != 0 {
		t.Fatalf("очередь должна быть пуста: %v", entries)
	}
	// Двойной выстрел (timeout-путь + planner-met) — дедуп по флагу.
	e.runAutoDistill(context.Background(), task, "done")
}

// TestBuildDistillContext — сборщик базы: находки (name/severity/summary из
// узлов), счётчики интентов по состояниям (done/exhausted/blocked), факты
// (включая origin-fact задачи).
func TestBuildDistillContext(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("distill ctx", "проверить веб-входы", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.Store.ID()) })
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := task.Store.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: tid, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "DIST", Name: "Distill fixture", Severity: "medium", Summary: "тестовая находка",
	}); err != nil {
		t.Fatal(err)
	}
	addIntent := func(state string) {
		t.Helper()
		id, err := task.Store.AddIntent(map[string]any{"summary": "intent " + state}, 5, nil, "test")
		if err != nil {
			t.Fatal(err)
		}
		if err := task.Store.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
	}
	addIntent("done")
	addIntent("exhausted")
	addIntent("blocked")
	addIntent("open")

	base, err := buildDistillContext(task, "timeout")
	if err != nil {
		t.Fatal(err)
	}
	if base.Status != "timeout" || base.Goal != "проверить веб-входы" {
		t.Fatalf("базовые поля: %+v", base)
	}
	if len(base.Findings) != 1 || base.Findings[0].Name != "Distill fixture" || base.Findings[0].Severity != "medium" {
		t.Fatalf("находки: %+v", base.Findings)
	}
	if base.Intents["done"] != 1 || base.Intents["exhausted"] != 1 || base.Intents["blocked"] != 1 || base.Intents["open"] != 1 {
		t.Fatalf("интенты: %+v", base.Intents)
	}
	if base.Facts < 1 { // origin-fact создаётся вместе с задачей
		t.Fatalf("факты: %d, want >= 1", base.Facts)
	}
}

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// reportTaskFixture creates one task with deterministic, task-scoped report
// content: a confirmed finding (which also gets a findings-table row → an
// evidence reference), an observed fact, an inferred fact and one task-owned
// root_domain asset. Everything is named after `label` so cross-task leakage in
// the report is assertable by substring.
func reportTaskFixture(t *testing.T, m *Manager, label string) (task *Task, taskID, findingID int64) {
	t.Helper()
	task, err := m.CreateTask("report scope "+label, "goal "+label, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ = strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, taskID)
		_ = m.pg.DeleteTask(taskID)
	})
	rec, err := task.Store.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: taskID, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "XSS", Name: label + " reflected XSS", Severity: "high",
		Summary:  label + "-only confirmed finding",
		Evidence: label + " raw poc with secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	findingID = rec.FindingID
	if _, err := task.Store.AddNode(db.KindFact, map[string]any{
		"summary": label + " observed: port 22 closed", "confidence": "observed",
	}, 0, "confirmed", "test", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddNode(db.KindFact, map[string]any{
		"summary": label + " inferred: admin panel likely elsewhere", "confidence": "inferred",
	}, 0, "confirmed", "test", nil); err != nil {
		t.Fatal(err)
	}
	domain := fmt.Sprintf("report-scope-%s-%d.example", label, time.Now().UnixNano())
	if _, err := m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: domain, TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	return task, taskID, findingID
}

func fetchReport(t *testing.T, s *Server, query string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/report"+query, nil)
	rec := httptest.NewRecorder()
	s.getReport(rec, req)
	return rec.Code, rec.Header(), rec.Body.String()
}

// TestGetReportTaskScoped: two disjoint tasks must produce two different
// reports — each shows only its own findings, evidence references, facts and
// assets (the old handler counted assets with the global QueryByType, mixing
// every project into every report).
func TestGetReportTaskScoped(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	taskA, _, findingA := reportTaskFixture(t, m, "alpha")
	taskB, _, findingB := reportTaskFixture(t, m, "beta")

	code, _, body := fetchReport(t, s, "?task="+taskA.ID+"&lang=en")
	if code != http.StatusOK {
		t.Fatalf("report A status=%d body=%s", code, body)
	}
	for _, want := range []string{
		"alpha-only confirmed finding",
		fmt.Sprintf("finding #%d", findingA),
		"alpha observed: port 22 closed",
		"alpha inferred: admin panel likely elsewhere",
		"root_domain 1",
		fmt.Sprintf("- **Task ID**: %s (exploration #%d)", taskA.ID, taskA.ExpID),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report A missing %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{
		"beta-only confirmed finding",
		fmt.Sprintf("finding #%d", findingB),
		"beta observed",
		"beta inferred",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("report A leaked task B content %q:\n%s", leak, body)
		}
	}
	// Asset counts are task-scoped (CountsByTypeForTask): task A owns exactly
	// one root_domain, so a global count would show 2.
	if !strings.Contains(body, "root_domain 1") {
		t.Errorf("report A asset counts not task-scoped:\n%s", body)
	}

	code, _, body = fetchReport(t, s, "?task="+taskB.ID+"&lang=en")
	if code != http.StatusOK {
		t.Fatalf("report B status=%d body=%s", code, body)
	}
	if !strings.Contains(body, "beta-only confirmed finding") || !strings.Contains(body, fmt.Sprintf("finding #%d", findingB)) {
		t.Errorf("report B missing its own finding/evidence:\n%s", body)
	}
	if strings.Contains(body, "alpha-only confirmed finding") || strings.Contains(body, fmt.Sprintf("finding #%d", findingA)) {
		t.Errorf("report B leaked task A content:\n%s", body)
	}
	if !strings.Contains(body, "root_domain 1") {
		t.Errorf("report B asset counts not task-scoped:\n%s", body)
	}
}

// TestGetReportLocalized: ?lang= renders ru and en skeletons, an unsupported
// locale falls back to English, and no ?lang= uses the server's active output
// language (pinned to ko for the test binary via ARTEX_LANG in TestMain, with
// the settings-table value reset for determinism).
func TestGetReportLocalized(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	// Pin the settings-table language away and restore it after (same contract
	// as output_language_test.go), so the no-lang case resolves deterministically
	// to ARTEX_LANG=ko pinned by TestMain.
	prev, hadPrev, _ := m.pg.GetSetting(settingOutputLanguage)
	defer func() {
		if hadPrev {
			_ = m.pg.SetSetting(settingOutputLanguage, prev)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingOutputLanguage)
		}
	}()
	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingOutputLanguage); err != nil {
		t.Fatal(err)
	}
	task, _, _ := reportTaskFixture(t, m, "loc")

	code, _, body := fetchReport(t, s, "?task="+task.ID+"&lang=ru")
	if code != http.StatusOK {
		t.Fatalf("ru status=%d body=%s", code, body)
	}
	if !strings.Contains(body, "# Отчёт о тестировании на проникновение: report scope loc") {
		t.Errorf("ru report not Russian:\n%s", body)
	}
	if strings.Contains(body, "Penetration Test Report") {
		t.Errorf("ru report contains English skeleton:\n%s", body)
	}

	code, _, body = fetchReport(t, s, "?task="+task.ID+"&lang=en")
	if code != http.StatusOK || !strings.Contains(body, "# Penetration Test Report: report scope loc") {
		t.Errorf("en report wrong (status=%d):\n%s", code, body)
	}

	code, _, body = fetchReport(t, s, "?task="+task.ID+"&lang=fr")
	if code != http.StatusOK {
		t.Fatalf("fr fallback status=%d body=%s", code, body)
	}
	if !strings.Contains(body, "# Penetration Test Report: report scope loc") || strings.Contains(body, "Отчёт о тестировании") {
		t.Errorf("unsupported locale did not fall back to English:\n%s", body)
	}

	code, _, body = fetchReport(t, s, "?task="+task.ID)
	if code != http.StatusOK {
		t.Fatalf("default-locale status=%d body=%s", code, body)
	}
	if !strings.Contains(body, "# 침투 테스트 보고서: report scope loc") {
		t.Errorf("default locale (active output language) not applied:\n%s", body)
	}
}

// TestGetReportEmptyTask: a task with no result at all is still a valid report:
// HTTP 200, zero counts, the honesty line — never a 500.
func TestGetReportEmptyTask(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	task, err := m.CreateTask("report empty task", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(tid) })

	code, _, body := fetchReport(t, s, "?task="+task.ID+"&lang=en")
	if code != http.StatusOK {
		t.Fatalf("empty task status=%d body=%s", code, body)
	}
	for _, want := range []string{
		"- Confirmed findings: **0**",
		"No confirmed vulnerabilities were recorded for this task.",
		"not proof that the targets are secure",
		"none recorded",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("empty report missing %q:\n%s", want, body)
		}
	}
}

// TestGetReportDownloadAndMissing: download=1 sets an attachment
// Content-Disposition; an unknown task stays 404.
func TestGetReportDownloadAndMissing(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	task, _, _ := reportTaskFixture(t, m, "dl")

	code, header, body := fetchReport(t, s, "?task="+task.ID+"&lang=en&download=1")
	if code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", code, body)
	}
	if disp := header.Get("Content-Disposition"); !strings.Contains(disp, `attachment; filename="report-task-`) {
		t.Errorf("download Content-Disposition missing: %q", disp)
	}

	code, _, _ = fetchReport(t, s, "?task=999999999")
	if code != http.StatusNotFound {
		t.Errorf("missing task status=%d want 404", code)
	}
}

// TestGetReportDatabaseFailureIsHTTP500: a dead database is an honest 500, not
// a fabricated empty report. The task is deleted BEFORE the pool is closed —
// a task leaked in a non-terminal state gets reloaded by later tests' managers
// and their planners then error against this dead pool.
func TestGetReportDatabaseFailureIsHTTP500(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	task, err := m.CreateTask("report dead db", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	if err := m.pg.DeleteTask(taskID); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	code, _, _ := fetchReport(t, s, "?task="+task.ID+"&lang=en")
	if code != http.StatusInternalServerError {
		t.Errorf("database failure status=%d want 500", code)
	}
}

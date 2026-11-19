package db

import (
	"context"
	"testing"
)

// TestFindingsDueForRetestSelection — таблица кейсов отбора находок к автопретесту:
// юная подтверждённая (моложе окна) не берётся; старая подтверждённая без ретестов
// берётся; активный ретест и свежий завершённый ретест исключают находку; старый
// завершённый ретест не блокирует; чужие triage-статусы (pending/fixed) не
// участвуют. Проверки — вхождением/невхождением, а не точным множеством: БД
// разработки общая, рядом могут лежать находки других тестов.
func TestFindingsDueForRetestSelection(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	newFinding := func(status string, ageDays int) int64 {
		t.Helper()
		fid, err := d.AddFinding(0, 0, "auto-retest-test", "自动复测筛选", "high", "summary", "evidence", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE findings SET status=$2, created_at=now()-make_interval(days=>$3::int) WHERE id=$1`,
			fid, status, ageDays); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
			_, _ = d.DeleteFinding(fid)
		})
		return fid
	}
	addRetest := func(fid int64, status string, ageDays int) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO finding_retests(finding_id, status, snapshot, created_at)
			VALUES ($1,$2,'{}'::jsonb, now()-make_interval(days=>$3::int))`, fid, status, ageDays); err != nil {
			t.Fatal(err)
		}
	}
	due := func(afterDays, limit int) map[int64]bool {
		t.Helper()
		ids, err := d.FindingsDueForRetest(context.Background(), afterDays, limit)
		if err != nil {
			t.Fatal(err)
		}
		out := make(map[int64]bool, len(ids))
		for _, id := range ids {
			out[id] = true
		}
		return out
	}

	oldConfirmed := newFinding(FindingConfirmed, 20)  // старая подтверждённая без ретестов → due
	youngConfirmed := newFinding(FindingConfirmed, 2) // юная подтверждённая (2 < 14) → не due
	oldPending := newFinding(FindingPending, 20)      // чужой статус → не due
	oldFixed := newFinding(FindingFixed, 30)          // fixed уже прошёл верификацию → не due
	activeRetest := newFinding(FindingConfirmed, 20)
	addRetest(activeRetest, "running", 20) // активный ретест → не due (и слот не тратим)
	recentRetest := newFinding(FindingConfirmed, 20)
	addRetest(recentRetest, "completed", 3) // свежий ретест (3 < 14) → не due
	staleRetest := newFinding(FindingConfirmed, 30)
	addRetest(staleRetest, "completed", 20) // старый ретест (20 ≥ 14) → снова due

	// Окно 14 дней, щедрый лимит.
	got := due(14, 100)
	if !got[oldConfirmed] || !got[staleRetest] {
		t.Fatalf("старые подтверждённые без свежего ретеста должны отбираться: %+v", got)
	}
	for _, id := range []int64{youngConfirmed, oldPending, oldFixed, activeRetest, recentRetest} {
		if got[id] {
			t.Fatalf("находка %d не должна отбираться (юная/чужой статус/активный или свежий ретест)", id)
		}
	}

	// ЛИМИТ 1 ретест-цель за проход.
	if got := due(14, 1); len(got) != 1 {
		t.Fatalf("лимит 1: получили %d целей, хотим 1", len(got))
	}

	// Сузили окно до 1 дня: юная (2 дн.) и «свежий ретест 3 дн.» становятся due,
	// активный ретест по-прежнему исключён.
	got = due(1, 200)
	if !got[youngConfirmed] || !got[recentRetest] {
		t.Fatalf("окно 1 день: юная и со свежим ретестом должны отбираться: %+v", got)
	}
	if got[activeRetest] {
		t.Fatal("активный ретест не должен отбираться ни при каком окне")
	}

	// Расширили окно до 21 дня: 20-дневные находки выходят из отбора.
	got = due(21, 200)
	if got[oldConfirmed] || got[staleRetest] {
		t.Fatalf("окно 21 день: 20-дневные находки не должны отбираться: %+v", got)
	}

	// afterDays=0: все подтверждённые due немедленно, кроме активного ретеста.
	got = due(0, 200)
	if !got[oldConfirmed] || !got[youngConfirmed] || got[activeRetest] {
		t.Fatalf("окно 0: все confirmed кроме активного ретеста: %+v", got)
	}

	// Некорректные параметры ограничиваются: afterDays<0 → 0, limit<=0 → 1.
	if got := due(-5, 0); len(got) != 1 {
		t.Fatalf("некорректные параметры: получили %d, хотим 1 (clamped)", len(got))
	}
}

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestAutoRetestIntervalFromSetting — парсер retest_interval_minutes по образцу
// TaskDefaultTimeout: пусто/нет ключа → дефолт 1ч; "0"/"off" (любой регистр) →
// выключено (0); нечисловое/отрицательное → дефолт; N → N минут.
func TestAutoRetestIntervalFromSetting(t *testing.T) {
	for _, tc := range []struct {
		v    string
		ok   bool
		want time.Duration
	}{
		{"", false, defaultRetestInterval},
		{"", true, defaultRetestInterval},
		{"   ", true, defaultRetestInterval},
		{"0", true, 0},
		{" 0 ", true, 0},
		{"off", true, 0},
		{"OFF", true, 0},
		{"Off", true, 0},
		{"abc", true, defaultRetestInterval},
		{"-5", true, defaultRetestInterval},
		{"1", true, time.Minute},
		{"90", true, 90 * time.Minute},
		{" 7 ", true, 7 * time.Minute},
	} {
		if got := autoRetestIntervalFrom(tc.v, tc.ok); got != tc.want {
			t.Errorf("autoRetestIntervalFrom(%q, %v) = %v, want %v", tc.v, tc.ok, got, tc.want)
		}
	}
}

// TestAutoRetestAfterDaysFromSetting — парсер retest_after_days: дефолт 14;
// "0" валиден (немедленный отбор); нечисловое/отрицательное → дефолт.
func TestAutoRetestAfterDaysFromSetting(t *testing.T) {
	for _, tc := range []struct {
		v    string
		ok   bool
		want int
	}{
		{"", false, defaultRetestAfterDays},
		{"", true, defaultRetestAfterDays},
		{"0", true, 0},
		{"7", true, 7},
		{" 30 ", true, 30},
		{"abc", true, defaultRetestAfterDays},
		{"-1", true, defaultRetestAfterDays},
	} {
		if got := autoRetestAfterDaysFrom(tc.v, tc.ok); got != tc.want {
			t.Errorf("autoRetestAfterDaysFrom(%q, %v) = %d, want %d", tc.v, tc.ok, got, tc.want)
		}
	}
}

// TestAutoRetestLoopLazyStartIdempotent — ленивый старт поднимает флаг ровно один
// раз (CompareAndSwap по образцу coordStarted); проход без pg/лаунчера — тихий
// no-op без паники (движок в тестовом окружении).
func TestAutoRetestLoopLazyStartIdempotent(t *testing.T) {
	e := NewEngine(&Manager{dir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.startAutoRetestLoop(ctx)                  // первый старт: флаг поднят, цикл мгновенно выходит (ctx отменён)
	e.startAutoRetestLoop(context.Background()) // повторный вызов — no-op
	if !e.autoRetestOn.Load() {
		t.Fatal("флаг цикла не поднят")
	}
	// Проход без подключённого pg — не паникует и ничего не делает.
	e.autoRetestPass(context.Background())
	e.autoRetestPass(context.Background())
	// Дефолты на nil-pg — как TaskDefaultTimeout.
	if got := e.autoRetestInterval(); got != defaultRetestInterval {
		t.Fatalf("interval nil-pg = %v, want %v", got, defaultRetestInterval)
	}
	if got := e.autoRetestAfterDays(); got != defaultRetestAfterDays {
		t.Fatalf("afterDays nil-pg = %d, want %d", got, defaultRetestAfterDays)
	}
}

// TestAutoRetestPassLaunchesThroughHook — проход по живой БД запускает РОВНО ОДИН
// ретест из отобранных находок (лимит за проход) через подключённый лаунчер;
// падающий и ошибающийся лаунчер не роняют проход (recover/лог + продолжение).
func TestAutoRetestPassLaunchesThroughHook(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	// Своя due-находка, чтобы отбор гарантированно был непуст (какие именно id
	// отберутся — неважно: соседние тесты могли оставить свои старые confirmed).
	fid, err := pg.AddFinding(0, 0, "retest-auto", "自动复测", "high", "s", "e", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE findings SET status='confirmed', created_at=now()-make_interval(days=>20) WHERE id=$1`, fid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
		_, _ = pg.DeleteFinding(fid)
	})
	e := NewEngine(&Manager{pg: pg, dir: t.TempDir()})

	var launched []int64
	e.SetRetestLauncher(func(_ context.Context, findingID int64, _ string) (bool, error) {
		launched = append(launched, findingID)
		return true, nil
	})
	e.autoRetestPass(context.Background())
	if len(launched) != 1 {
		t.Fatalf("за проход должен запускаться ровно 1 ретест, launched=%v", launched)
	}

	// Лаунчер-паника гасится recover на проходе, наружу не роняется.
	e.SetRetestLauncher(func(context.Context, int64, string) (bool, error) {
		panic("test launcher panic")
	})
	e.autoRetestPass(context.Background())

	// Лаунчер-ошибка — лог и продолжение (никакого наружного err/паники).
	e.SetRetestLauncher(func(context.Context, int64, string) (bool, error) {
		return false, errors.New("agent disabled")
	})
	e.autoRetestPass(context.Background())

	// created=false (активный ретест уже есть) — не ошибка, молча.
	e.SetRetestLauncher(func(context.Context, int64, string) (bool, error) {
		return false, nil
	})
	e.autoRetestPass(context.Background())
}

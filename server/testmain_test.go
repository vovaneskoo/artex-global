package server

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/testutil"
)

// TestMain resolves this suite's database and holds the cross-package advisory
// lock (7337741002) for the entire run.
//
// The database comes from testutil: a disposable postgres:16-alpine container
// unless an explicitly exported ARTEX_TEST_PG_DSN/ARTEX_PG_DSN (CI) provides a
// shared one — never the working database a config.json might describe, which
// testutil shadows for the whole binary. Cross-package DELETE cleanup races
// with db/agent only matter in shared-database mode; the lock covers those.
func TestMain(m *testing.M) {
	// server.New starts the realtime notifier's background delivery loop
	// (notifyTick) unless this env var is set. The notify integration tests
	// drive stepRealtime/stepDigest directly (see newNotifyFixture) and only
	// that fixture disabled the loop per-test. Other tests construct a server
	// with a live context.Background() that is never cancelled, so their
	// notifier goroutine leaks and keeps ticking for the rest of the binary;
	// when it fires inside a later test's window it claims that test's
	// deliveries out of band and corrupts the exact per-delivery attempt
	// accounting. That is what made TestNotifyDeliveriesHistoryAndRetry flake
	// intermittently ("重试耗尽后应为 failed，得到 pending"). No test asserts on the
	// background loop itself, so disable it suite-wide for determinism; the
	// loop's dispatch is covered through direct stepRealtime/stepDigest calls.
	os.Setenv(notifyBackgroundDisabledEnv, "1")
	// The server suite verifies the Korean localization of user-facing output,
	// so pin the default output language to Korean for the whole test binary.
	// Production defaults to English (config.DefaultLanguage); individual tests
	// that need another language set it explicitly (t.Setenv / the settings table).
	os.Setenv("ARTEX_LANG", "ko")

	os.Exit(testutil.RunPGSuite(m, func(dsn string) int {
		return testutil.WithSuiteLock(dsn, m.Run)
	}))
}

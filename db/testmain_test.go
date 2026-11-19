package db

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
// shared one. This is what keeps the suite away from a working database that
// env vars or a config.json might otherwise point db.DSN() at — testutil
// shadows both for the whole binary. Tests that need PG skip themselves when
// no database is available.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunPGSuite(m, func(dsn string) int {
		return testutil.WithSuiteLock(dsn, m.Run)
	}))
}

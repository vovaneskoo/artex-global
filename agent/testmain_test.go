package agent

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/testutil"
)

// TestMain resolves this suite's database (disposable container by default,
// see testutil) and holds the cross-package advisory lock (7337741002) for the
// entire run so cross-package DELETE cleanup races with db/server packages are
// avoided when the suites share one database.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunPGSuite(m, func(dsn string) int {
		return testutil.WithSuiteLock(dsn, m.Run)
	}))
}

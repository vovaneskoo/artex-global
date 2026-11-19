package evidence

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/testutil"
)

// Initialize the suite's database (disposable container by default, see
// testutil; an explicitly exported DSN is honored) before taking the same
// suite lock as db, agent and server. The lock is held on one pinned
// connection so the unlock hits the same PostgreSQL session.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunPGSuite(m, func(dsn string) int {
		return testutil.WithSuiteLock(dsn, func() int {
			if dsn == "" {
				return m.Run()
			}
			pg, err := db.Open(dsn)
			if err != nil {
				panic(err)
			}
			defer pg.Close()
			return m.Run()
		})
	}))
}

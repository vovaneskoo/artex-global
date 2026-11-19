package testutil

import (
	"database/sql"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func dockerAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
		return false
	}
	return true
}

// containerExists reports whether Docker still knows a container by name
// (running or stopped).
func containerExists(t *testing.T, name string) bool {
	t.Helper()
	out, err := dockerCommand("ps", "-aq", "--filter", "name=^/"+name+"$")
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	return strings.TrimSpace(string(out)) != ""
}

// TestDisposablePostgresLifecycle pins the happy path: a container starts on a
// Docker-assigned port, the DSN really connects, and Close removes the
// container (the database is disposable — nothing may outlive the run).
func TestDisposablePostgresLifecycle(t *testing.T) {
	if !dockerAvailable(t) {
		return
	}
	g := startDisposablePostgres(nil)
	if g.DSN() == "" {
		t.Fatal("disposable postgres did not become ready")
	}
	t.Cleanup(g.Close)
	conn, err := sql.Open("pgx", g.DSN())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	var one int
	if err := conn.QueryRow(`SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("ping via DSN: one=%d err=%v", one, err)
	}
	name := g.Container()
	if name == "" {
		t.Fatal("guard did not report its container name")
	}
	g.Close()
	if containerExists(t, name) {
		t.Fatalf("container %s still exists after Close — teardown must delete the disposable DB", name)
	}
}

// TestSetupFailureLeavesNoContainer pins the early-cleanup contract: when the
// readiness probe fails (here: the container runs `sleep` instead of postgres),
// setup must still remove the container. A setup that dies midway may not leave
// garbage behind.
func TestSetupFailureLeavesNoContainer(t *testing.T) {
	if !dockerAvailable(t) {
		return
	}
	oldTimeout := postgresReadyTimeout
	postgresReadyTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { postgresReadyTimeout = oldTimeout })

	// `sh -c "sleep 120"`: the container publishes no port and never becomes
	// ready, so the probe inside startDisposablePostgres fails.
	g := startDisposablePostgres([]string{"sh", "-c", "sleep 120"})
	if g.DSN() != "" {
		t.Fatalf("expected no DSN from a never-ready container, got one (container %s)", g.Container())
	}
	// startDisposablePostgres defers Close on every exit path; by the time it
	// returned, the container must already be gone.
	name := g.Container()
	if name == "" {
		t.Fatal("expected the failed setup to still report the container it started")
	}
	if containerExists(t, name) {
		t.Fatalf("container %s survived a failed setup — early cleanup registration is broken", name)
	}
}

// TestPreserveTableRestoresSharedFixtureState pins the fixture-restore helper:
// rows a test adds are deleted, rows it deletes or modifies come back — the
// llm_profiles/settings state later tests see is the state earlier tests found,
// whatever the test order.
func TestPreserveTableRestoresSharedFixtureState(t *testing.T) {
	if !dockerAvailable(t) {
		return
	}
	g := startDisposablePostgres(nil)
	if g.DSN() == "" {
		t.Skip("disposable postgres unavailable")
	}
	t.Cleanup(g.Close)
	pg, err := db.Open(g.DSN())
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	defer pg.Close()

	// Shared fixture before any preserving test: one active profile + one setting.
	keepID, err := pg.SaveProfile(&db.LLMProfile{Name: "fixture-active", Format: "openai", Model: "m", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.SetActiveProfile(keepID); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting("t_preserve_fixture", "before"); err != nil {
		t.Fatal(err)
	}

	// The "mutating test": preserve, then flip active profile + settings the
	// way TestConfigStores-style tests do.
	testDone := func(t *testing.T) {
		PreserveTable(t, pg.DB, "llm_profiles")
		PreserveTable(t, pg.DB, "settings")
		mutID, err := pg.SaveProfile(&db.LLMProfile{Name: "mutator", Format: "openai", Model: "m", APIKey: "k2"})
		if err != nil {
			t.Fatal(err)
		}
		if err := pg.SetActiveProfile(mutID); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Exec(`DELETE FROM llm_profiles WHERE id=$1`, keepID); err != nil {
			t.Fatal(err)
		}
		if err := pg.SetSetting("t_preserve_fixture", "after"); err != nil {
			t.Fatal(err)
		}
		if err := pg.SetSetting("t_preserve_added", "gone-after-cleanup"); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("mutating test", testDone)

	// After the inner test's cleanups ran, the original fixture must be back.
	act, err := pg.ActiveProfile()
	if err != nil || act == nil || act.ID != keepID {
		t.Fatalf("active profile after restore = %+v err=%v, want id=%d", act, err, keepID)
	}
	v, ok, err := pg.GetSetting("t_preserve_fixture")
	if err != nil || !ok || v != "before" {
		t.Fatalf("setting after restore = %q ok=%v err=%v, want %q", v, ok, err, "before")
	}
	if _, ok, _ := pg.GetSetting("t_preserve_added"); ok {
		t.Fatal("setting added by the test must be removed by restore")
	}
}

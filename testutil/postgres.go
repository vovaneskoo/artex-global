// Package testutil centralizes the database lifecycle for DB-backed test
// suites (agent, db, evidence, server).
//
// Hazard it removes: db.DSN() resolves env ARTEX_PG_DSN, else the config file.
// A developer shell with an exported ARTEX_PG_DSN (or a config.json later found
// via config.Path()) would silently point the whole integration suite at the
// WORKING application database, and tests that flip global fixture state
// (SetActiveProfile, settings rows) would corrupt it.
//
// Contract here:
//
//   - An explicitly exported ARTEX_TEST_PG_DSN / ARTEX_PG_DSN (CI jobs export
//     it) is honored verbatim — opt-in shared-database mode.
//   - Otherwise each test binary gets its own disposable postgres:16-alpine
//     container on a Docker-assigned free local port. The chosen DSN is
//     exported as ARTEX_PG_DSN so db.DSN() resolves to it, which also shadows
//     any config-file database entry for the whole binary.
//   - When neither is possible (no docker), ARTEX_CONFIG is pointed at a
//     missing file so DSN() still cannot fall through to a working config.json;
//     DB tests then skip themselves exactly as before.
//   - Teardown (docker rm -f) is registered before the first readiness probe,
//     so a setup that dies mid-way — failed probe, panic in TestMain — still
//     leaves no container behind.
//
// The DSN value itself is never logged (it carries credentials).
package testutil

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // driver for readiness probes and suite lock
)

const (
	disposableImage    = "postgres:16-alpine"
	disposableUser     = "artex"
	disposablePassword = "artex"
	disposableDBName   = "artex"
	// containerLabel marks every container started here, so operators can
	// identify (and clean up) leftovers after a killed run:
	//   docker ps -a --filter label=artex.testpg=1
	containerLabel = "artex.testpg"
	// readyTimeout bounds the readiness poll after `docker run` returned
	// (postgres initdb inside the container takes a couple of seconds).
	readyTimeout = 90 * time.Second
	// dockerCommandTimeout bounds each individual docker CLI invocation.
	dockerCommandTimeout = 5 * time.Minute
)

// suiteLockKey is the cross-package advisory lock the DB-backed suites hold for
// their whole run when they share ONE database (env-provided DSN mode). With a
// per-binary disposable database the lock is a local no-op, but keeping it in
// both modes means shared-database runs (CI, ARTEX_PG_DSN) serialize exactly as
// before. The value is the historical key; changing it would let an old and a
// new binary interleave their cleanups.
const suiteLockKey int64 = 7337741002

// PostgresGuard owns the database one test binary runs against. The zero value
// (and a nil guard) mean "no database available": all DSN() == "" and DB tests
// skip themselves.
type PostgresGuard struct {
	dsn       string
	container string // "" for env-provided DSNs — nothing to tear down
	closed    bool
}

// DSN returns the resolved connection string ("" when no database is
// available). Callers must not log it: it embeds credentials.
func (g *PostgresGuard) DSN() string {
	if g == nil {
		return ""
	}
	return g.dsn
}

// Container returns the disposable container's Docker name ("" in
// shared-database mode). Exposed for tests asserting the teardown.
func (g *PostgresGuard) Container() string {
	if g == nil {
		return ""
	}
	return g.container
}

// External reports whether the DSN came from the environment (shared-database
// mode) rather than a disposable container.
func (g *PostgresGuard) External() bool {
	if g == nil {
		return false
	}
	return g.container == "" && g.dsn != ""
}

// Close tears the guard down. It is idempotent and never fails the caller: a
// teardown problem is logged (without the DSN) and the suite result stands.
func (g *PostgresGuard) Close() {
	if g == nil || g.closed || g.container == "" {
		if g != nil {
			g.closed = true
		}
		return
	}
	g.closed = true
	name := g.container
	if out, err := dockerCommand("rm", "-f", name); err != nil {
		log.Printf("[testpg] teardown: removing container %s failed: %v: %s", name, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[testpg] disposable postgres %s removed", name)
}

// ResolvePostgres decides the DSN for this test binary (see package comment)
// and installs the matching process environment:
//
//   - disposable mode: ARTEX_PG_DSN is set to the container DSN, shadowing any
//     config-file database for the rest of the binary;
//   - no-database mode: ARTEX_CONFIG is pointed at a missing file so DSN()
//     cannot silently fall through to a working config.json.
//
// It never returns an error: an unavailable database is a normal outcome and
// the suite must still run (with DB tests skipping), not abort.
func ResolvePostgres() *PostgresGuard {
	if dsn := strings.TrimSpace(os.Getenv("ARTEX_TEST_PG_DSN")); dsn != "" {
		return disableConfigFallback(&PostgresGuard{dsn: dsn}, "ARTEX_TEST_PG_DSN")
	}
	if dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")); dsn != "" {
		return disableConfigFallback(&PostgresGuard{dsn: dsn}, "ARTEX_PG_DSN")
	}
	g := startDisposablePostgres(nil)
	if g.DSN() == "" {
		return disableConfigFallback(g, "")
	}
	os.Setenv("ARTEX_PG_DSN", g.dsn) //nolint:errcheck // env of our own process
	return g
}

// disableConfigFallback points ARTEX_CONFIG at a file that does not exist.
// config.Path() resolves env ARTEX_CONFIG first, and Load() of a missing file
// is a zero Config — so PostgresDSN() errors instead of ever reading a real
// config.json, and DB tests skip. This keeps the no-container path from
// silently connecting to the working database.
func disableConfigFallback(g *PostgresGuard, via string) *PostgresGuard {
	if via != "" {
		log.Printf("[testpg] using externally provided %s — shared-database mode (no disposable container)", via)
	}
	os.Setenv("ARTEX_CONFIG", filepath.Join(os.TempDir(), fmt.Sprintf("artex-test-no-config-%d.json", os.Getpid()))) //nolint:errcheck
	return g
}

func dockerCommand(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// postgresReadyTimeout is a variable so tests can shrink the probe window.
var postgresReadyTimeout = readyTimeout

// startDisposablePostgres runs postgres:16-alpine on a Docker-assigned free
// local port. Cleanup is armed the moment `docker run` succeeds — BEFORE the
// readiness probe — so any later failure (probe timeout, panic) still removes
// the container.
//
// cmdOverride replaces the image's command (entrypoint arguments) and exists
// solely for tests of the failure path; production passes nil.
func startDisposablePostgres(cmdOverride []string) *PostgresGuard {
	if _, err := exec.LookPath("docker"); err != nil {
		log.Printf("[testpg] docker not found — DB tests will skip")
		return &PostgresGuard{}
	}
	// Pull explicitly so a cold image cache blocks in `docker pull` (visible
	// progress) instead of inside an opaque `docker run`.
	if _, err := dockerCommand("image", "inspect", disposableImage); err != nil {
		log.Printf("[testpg] pulling %s (first run may take a while)", disposableImage)
		if out, err := dockerCommand("pull", disposableImage); err != nil {
			log.Printf("[testpg] image pull failed — DB tests will skip: %v: %s", err, firstLine(out))
			return &PostgresGuard{}
		}
	}

	name := fmt.Sprintf("artex-testpg-%d-%s", os.Getpid(), randHex(4))
	runArgs := []string{"run", "-d", "--rm",
		"--label", containerLabel + "=1",
		"--name", name,
		"-p", "127.0.0.1::5432",
		"-e", "POSTGRES_USER=" + disposableUser,
		"-e", "POSTGRES_PASSWORD=" + disposablePassword,
		"-e", "POSTGRES_DB=" + disposableDBName,
	}
	if len(cmdOverride) > 0 {
		runArgs = append(runArgs, "--entrypoint", cmdOverride[0])
	}
	runArgs = append(runArgs, disposableImage)
	if len(cmdOverride) > 1 {
		runArgs = append(runArgs, cmdOverride[1:]...) // command arguments go after the image
	}
	if out, err := dockerCommand(runArgs...); err != nil {
		log.Printf("[testpg] docker run failed — DB tests will skip: %v: %s", err, firstLine(out))
		return &PostgresGuard{}
	}
	// From the moment the container exists, EVERY failure path below must tear
	// it down again (defer-style early cleanup): a setup that dies midway may
	// not leave garbage behind. The guard keeps the container name so callers
	// and tests can still see what was started and removed.
	g := &PostgresGuard{container: name}
	fail := func(format string, args ...any) *PostgresGuard {
		log.Printf("[testpg] "+format, args...)
		g.Close()
		return g // DSN stays "" — the suite runs with DB tests skipping
	}

	port, err := containerPort(name)
	if err != nil {
		return fail("resolving published port failed: %v", err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		disposableUser, disposablePassword, port, disposableDBName)
	if err := waitPostgresReady(dsn, postgresReadyTimeout); err != nil {
		return fail("disposable postgres did not become ready: %v", err)
	}
	g.dsn = dsn
	log.Printf("[testpg] disposable postgres ready (container %s, port %s)", name, port)
	return g
}

// containerPort asks Docker for the host port it published for 5432. Letting
// Docker pick the port (host side of -p is empty) avoids the classic
// bind-then-release race of choosing a "free" port ourselves when several
// package binaries start containers in parallel.
func containerPort(name string) (string, error) {
	out, err := dockerCommand("port", name, "5432")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		// "5432/tcp -> 127.0.0.1:55123" (or an [::]: form — skip it, we bound 127.0.0.1)
		if at := strings.LastIndex(line, "127.0.0.1:"); at >= 0 {
			port := strings.TrimSpace(line[at+len("127.0.0.1:"):])
			if port != "" {
				return port, nil
			}
		}
	}
	return "", fmt.Errorf("no published 127.0.0.1 port in %q", firstLine(out))
}

func waitPostgresReady(dsn string, timeout time.Duration) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	deadline := time.Now().Add(timeout)
	for {
		err := db.Ping()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ping: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// RunPGSuite wires the disposable-postgres lifecycle around a TestMain body.
// The guard's teardown runs on every path — including a panic inside body
// (defers unwind) — so a failing setup or suite never leaks a container.
func RunPGSuite(m *testing.M, body func(dsn string) int) int {
	g := ResolvePostgres()
	defer g.Close()
	return body(g.DSN())
}

// WithSuiteLock runs body while holding the cross-package advisory lock on dsn
// (see suiteLockKey). An empty dsn (no database) just runs the body. The lock
// lives on one pinned connection: *sql.DB pooling would otherwise run the
// unlock on a different PostgreSQL session and never release it.
func WithSuiteLock(dsn string, body func() int) int {
	if dsn == "" {
		return body()
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return body()
	}
	defer conn.Close()
	if err := conn.Ping(); err != nil {
		return body()
	}
	c, err := conn.Conn(context.Background())
	if err != nil {
		return body()
	}
	defer c.Close()
	if _, err := c.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, suiteLockKey); err != nil {
		return body()
	}
	defer c.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, suiteLockKey) //nolint:errcheck
	return body()
}

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256)) //nolint:gosec // test container names, not crypto
	}
	return hex.EncodeToString(b)
}

func firstLine(out []byte) string {
	s := strings.TrimSpace(string(out))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

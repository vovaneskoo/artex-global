package traffic

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Permission policy for the local traffic tree (see docs/privacy-map.md):
// captured bodies, the SQLite index and the MITM CA key are readable by the
// service account only. Directories 0700, files 0600 — owner keeps full
// access, other local accounts get nothing. Ownership is never changed, and
// migration only calls chmod, so file bytes and open file descriptors of
// running readers/writers are untouched.
const (
	privateDirMode  fs.FileMode = 0o700
	privateFileMode fs.FileMode = 0o600
)

// MigratePermissions tightens an existing traffic tree in place: every
// directory to 0700, every regular file to 0600. It is idempotent and runs on
// every Open, so trees created by older builds (0755/0644) converge without a
// separate migration step. Symlinks are skipped — chmod would follow them and
// touch targets outside the tree. Errors are returned but a failing entry does
// not stop the walk of the remaining entries.
func MigratePermissions(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := privateDirMode
		switch {
		case d.IsDir():
		case d.Type()&fs.ModeSymlink != 0:
			return nil
		case d.Type().IsRegular():
			mode = privateFileMode
		default:
			// Fifos, sockets and device nodes do not occur in the tree; leave them.
			return nil
		}
		if info, statErr := d.Info(); statErr == nil && info.Mode().Perm() == mode {
			return nil // already tight; skip the chmod syscall
		}
		return os.Chmod(path, mode)
	})
}

// secureSQLiteFiles chmods the index database and its WAL/SHM siblings to 0600
// when they exist. SQLite (modernc driver) creates these with the process
// umask and offers no creation-mode option, so this runs right after the first
// write transaction of each start. Missing siblings are not an error: -wal and
// -shm appear only once WAL mode writes happen and are removed again on clean
// close.
func secureSQLiteFiles(index string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := index + suffix
		if info, err := os.Stat(p); err == nil && info.Mode().Perm() != privateFileMode {
			_ = os.Chmod(p, privateFileMode)
		}
	}
}

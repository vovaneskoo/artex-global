package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// treeModes walks dir and returns path → permission bits for every directory
// and regular file (symlinks and specials skipped), for assertions.
func treeModes(t *testing.T, root string) map[string]os.FileMode {
	t.Helper()
	modes := map[string]os.FileMode{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type().IsRegular() {
			info, statErr := d.Info()
			if statErr != nil {
				return statErr
			}
			rel, _ := filepath.Rel(root, path)
			modes[rel] = info.Mode().Perm()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return modes
}

func assertMode(t *testing.T, modes map[string]os.FileMode, rel string, want os.FileMode) {
	t.Helper()
	got, ok := modes[rel]
	if !ok {
		t.Fatalf("expected entry %q in permission tree, got none (tree: %v)", rel, modes)
	}
	if got != want {
		t.Errorf("%s: permissions %o, want %o", rel, got, want)
	}
}

// TestOpenCreatesPrivateTree verifies that a fresh store lays out every
// sensitive artifact — SQLite index (+WAL/SHM), spilled blobs, directory
// buckets — as owner-only, regardless of the inherited umask.
func TestOpenCreatesPrivateTree(t *testing.T) {
	if old := umaskTest(0o022); old >= 0 {
		defer umaskTest(old)
	}
	tr, dir := openTraffic(t)

	// A body above maxInlineBody (256 KiB) forces a spill into _blobs.
	big := make([]byte, maxInlineBody+4096)
	for i := range big {
		big[i] = byte('a' + i%26)
	}
	tr.record(newFlow("secret.example.com", "POST", "/v1/login", big, big))

	modes := treeModes(t, dir)
	for _, d := range []string{".", "_index", "_blobs", "_ca"} {
		assertMode(t, modes, d, 0o700)
	}
	assertMode(t, modes, filepath.Join("_index", "index.sqlite"), 0o600)
	// WAL/SHM are created by the first write transaction; when present they
	// must already be tightened (they carry body fragments).
	if got, ok := modes[filepath.Join("_index", "index.sqlite-wal")]; ok && got != 0o600 {
		t.Errorf("index.sqlite-wal: permissions %o, want 600", got)
	}
	if got, ok := modes[filepath.Join("_index", "index.sqlite-shm")]; ok && got != 0o600 {
		t.Errorf("index.sqlite-shm: permissions %o, want 600", got)
	}

	// The spilled blob must be 0600 inside a 0700 bucket.
	sum := sha256.Sum256(big)
	h := hex.EncodeToString(sum[:])
	blobRel := filepath.Join("_blobs", "sha256", h[:2], h+".bin")
	assertMode(t, modes, filepath.Dir(blobRel), 0o700)
	assertMode(t, modes, blobRel, 0o600)
}

// umaskTest sets the process umask for the duration of a test and returns the
// previous value (or -1 on error, in which case the caller ignores it). Used
// to prove creation modes come from the explicit 0700/0600, not a lucky umask.
func umaskTest(mask int) int {
	old := syscallUmask(mask)
	return old
}

// TestMigratePermissionsPreservesBytes builds a tree the way an older build
// left it (0755 dirs, 0644 files), migrates it, and checks that every mode is
// tightened while every file's content checksum is bit-for-bit identical.
func TestMigratePermissionsPreservesBytes(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{}
	mk := func(rel, content string, fileMode os.FileMode) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), fileMode); err != nil {
			t.Fatal(err)
		}
		files[rel] = content
	}
	mk(filepath.Join("_index", "index.sqlite"), "sqlite-bytes", 0o644)
	mk(filepath.Join("_index", "index.sqlite-wal"), "wal-bytes", 0o644)
	mk(filepath.Join("_index", "index.sqlite-shm"), "shm-bytes", 0o644)
	mk(filepath.Join("_blobs", "sha256", "ab", "deadbeef.bin"), "blob-bytes", 0o644)
	mk(filepath.Join("_ca", "mitmproxy-ca.pem"), "ca-key-bytes", 0o600)
	mk(filepath.Join("_ca", "mitmproxy-ca-cert.pem"), "ca-cert-bytes", 0o644)

	before := fileChecksums(t, dir)
	if err := MigratePermissions(dir); err != nil {
		t.Fatalf("MigratePermissions: %v", err)
	}
	after := fileChecksums(t, dir)
	if len(before) == 0 {
		t.Fatal("no files checksummed before migration")
	}
	for rel, sum := range before {
		if after[rel] != sum {
			t.Errorf("%s: content changed by migration (%s → %s)", rel, sum, after[rel])
		}
	}
	if len(before) != len(after) {
		t.Errorf("file count changed: %d before, %d after", len(before), len(after))
	}

	modes := treeModes(t, dir)
	for _, d := range []string{".", "_index", "_blobs", filepath.Join("_blobs", "sha256"), filepath.Join("_blobs", "sha256", "ab"), "_ca"} {
		assertMode(t, modes, d, 0o700)
	}
	for rel := range files {
		assertMode(t, modes, rel, 0o600)
	}

	// Idempotent: a second pass changes nothing and still succeeds.
	if err := MigratePermissions(dir); err != nil {
		t.Fatalf("second MigratePermissions: %v", err)
	}
}

// TestMigratePermissionsSkipsSymlinks ensures chmod never follows a symlink
// planted inside the tree out to a file outside it.
func TestMigratePermissionsSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep 0644"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := MigratePermissions(dir); err != nil {
		t.Fatalf("MigratePermissions: %v", err)
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("outside target followed through symlink: %o, want 644", info.Mode().Perm())
	}
}

func fileChecksums(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, _ := filepath.Rel(root, path)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestImportArchiveRestoresPrivateBlobs covers the archive import path: blobs
// landing back in _blobs after a restore must be 0600 in a 0700 bucket.
func TestImportArchiveRestoresPrivateBlobs(t *testing.T) {
	if old := umaskTest(0o022); old >= 0 {
		defer umaskTest(old)
	}
	tr, dir := openTraffic(t)

	// Build a minimal archive snapshot with one blob.
	body := []byte(fmt.Sprintf("archived-secret-%0256d", 1))
	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	arch := t.TempDir()
	if err := os.MkdirAll(filepath.Join(arch, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arch, "blobs", h+".bin"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// ImportArchive re-writes missing blobs through the spill layout.
	// Direct call on a fresh hash: emulate via importing into the live store.
	snap := fmt.Sprintf(`{"version":1,"exchanges":[],"blobs":["%s"]}`, h)
	if err := os.WriteFile(filepath.Join(arch, "traffic.json"), []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.ImportArchive(arch); err != nil {
		t.Fatalf("ImportArchive: %v", err)
	}
	modes := treeModes(t, dir)
	blobRel := filepath.Join("_blobs", "sha256", h[:2], h+".bin")
	assertMode(t, modes, filepath.Dir(blobRel), 0o700)
	assertMode(t, modes, blobRel, 0o600)
}

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestSecureLocalDataTightensTranscripts builds a data root the way an older
// build left it (0755 dirs, 0644 transcript files), runs secureLocalData and
// checks: modes tightened to owner-only, file bytes bit-for-bit identical,
// idempotent on a second run.
func TestSecureLocalDataTightensTranscripts(t *testing.T) {
	dir := t.TempDir()
	sess := filepath.Join(dir, "transcripts", "exp1-worker-i3")
	if err := os.MkdirAll(sess, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join("transcripts", "exp1-planner.jsonl"):           `{"role":"user","text":"canary-secret-1"}`,
		filepath.Join("transcripts", "exp1-worker-i3", "turn.jsonl"): `{"role":"assistant","text":"canary-secret-2"}`,
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	before := checksumTree(t, dir)
	if err := secureLocalData(dir); err != nil {
		t.Fatalf("secureLocalData: %v", err)
	}
	after := checksumTree(t, dir)
	if len(before) != len(after) {
		t.Fatalf("file count changed: %d before, %d after", len(before), len(after))
	}
	for rel, sum := range before {
		if after[rel] != sum {
			t.Errorf("%s: content changed by migration (%s → %s)", rel, sum, after[rel])
		}
	}

	assertPerm(t, dir, 0o700)
	assertPerm(t, filepath.Join(dir, "transcripts"), 0o700)
	assertPerm(t, sess, 0o700)
	for rel := range files {
		assertPerm(t, filepath.Join(dir, rel), 0o600)
	}

	if err := secureLocalData(dir); err != nil {
		t.Fatalf("second secureLocalData: %v", err)
	}
	assertPerm(t, filepath.Join(dir, "transcripts"), 0o700)
}

// TestSecureLocalDataCreatesTranscriptsPrivate verifies the transcripts
// directory is pre-created 0700 on a fresh root, before transcript.NewStore
// ever writes into it.
func TestSecureLocalDataCreatesTranscriptsPrivate(t *testing.T) {
	dir := t.TempDir()
	// Simulate the older 0755 root creation, then the new code path.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := secureLocalData(dir); err != nil {
		t.Fatalf("secureLocalData: %v", err)
	}
	assertPerm(t, dir, 0o700)
	assertPerm(t, filepath.Join(dir, "transcripts"), 0o700)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s: permissions %o, want %o", path, info.Mode().Perm(), want)
	}
}

func checksumTree(t *testing.T, root string) map[string]string {
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

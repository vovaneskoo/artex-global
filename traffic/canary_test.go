package traffic

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// worldReadable returns every entry under root whose permission bits allow
// group or other access (policy: dirs 0700, files 0600).
func worldReadable(t *testing.T, root string) []string {
	t.Helper()
	var leak []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			kind := "file"
			if d.IsDir() {
				kind = "dir"
			}
			leak = append(leak, fmt.Sprintf("%s %s: %o", kind, path, info.Mode().Perm()))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return leak
}

// canaryOnDisk reports whether the secret string appears anywhere in the
// store's persisted bytes: the SQLite index (inline bodies) or a spilled blob.
func canaryOnDisk(t *testing.T, dir, secret string) bool {
	t.Helper()
	idx, err := os.ReadFile(filepath.Join(dir, "_index", "index.sqlite"))
	if err == nil && bytes.Contains(idx, []byte(secret)) {
		return true
	}
	found := false
	_ = filepath.WalkDir(filepath.Join(dir, "_blobs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr == nil && bytes.Contains(data, []byte(secret)) {
			found = true
		}
		return nil
	})
	return found
}

// TestCanarySecretNotWorldReadable is the canary probe. A synthetic secret
// ("CANARY-SECRET-7f3a9c1e" — never a real credential) is pushed through the
// real capture path: an inline SQLite body row and a spilled _blobs file.
// Open's own artifacts must already be owner-only with no extra pass; a
// transcript-style file written the way the norma dependency writes them
// (0644, no creation-mode knob) is the one allowed exception until the
// start-time MigratePermissions pass tightens it, after which nothing in the
// canary tree may be group/other-accessible.
func TestCanarySecretNotWorldReadable(t *testing.T) {
	tr, dir := openTraffic(t)
	secret := "CANARY-SECRET-7f3a9c1e"
	big := []byte(secret + fmt.Sprintf("%0*d", maxInlineBody, 0)) // exceeds maxInlineBody → spills
	tr.record(newFlow("canary.example.com", "POST", "/v1/auth", []byte(secret), big))

	// The canary must really be in the store, or the probe proves nothing.
	if !canaryOnDisk(t, dir, secret) {
		t.Fatal("canary secret not found in index/blobs — probe is not exercising the store")
	}

	// Simulate the norma transcript dependency: a 0644 file inside the tree.
	transcriptPath := filepath.Join(dir, "canary-transcript.jsonl")
	if err := os.WriteFile(transcriptPath, []byte(`{"secret":"`+secret+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Everything Open itself produced must already be private — the only
	// allowed wide-open entry is the dep-simulated transcript file.
	for _, l := range worldReadable(t, dir) {
		if !bytes.Contains([]byte(l), []byte(transcriptPath)) {
			t.Errorf("artifact created by Open is group/other-accessible: %s", l)
		}
	}

	// The start-time migration pass must leave zero world-accessible entries.
	if err := MigratePermissions(dir); err != nil {
		t.Fatal(err)
	}
	if leaks := worldReadable(t, dir); len(leaks) > 0 {
		for _, l := range leaks {
			t.Errorf("still world-accessible after migration: %s", l)
		}
	}
}

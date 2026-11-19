package server

import (
	"os"
	"path/filepath"

	"github.com/Autumn-27/artex/traffic"
)

// secureLocalData tightens the service data root and the transcript tree to
// owner-only permissions (dirs 0700, files 0600), leaving bytes and ownership
// untouched. It runs on every Manager start, so installs laid out by older
// builds with 0755/0644 converge without a separate migration step.
//
// The transcript files themselves are written by the norma transcript.Store
// (an external dependency) with 0644 and no creation-mode knob; the 0700
// directory boundary is what keeps them private, and the walk below brings
// already-written files to 0600 as well. New transcript files created later
// stay 0644 on disk but remain unreachable to other local accounts because
// every directory above them is 0700.
func secureLocalData(dir string) error {
	if info, err := os.Stat(dir); err == nil && info.IsDir() && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	// Pre-create with 0700 before transcript.NewStore ever sees the path: the
	// store's own MkdirAll keeps existing modes, so this pins the boundary.
	transcripts := filepath.Join(dir, "transcripts")
	if err := os.MkdirAll(transcripts, 0o700); err != nil {
		return err
	}
	// Same walk semantics as the traffic tree (dirs 0700, files 0600).
	return traffic.MigratePermissions(transcripts)
}

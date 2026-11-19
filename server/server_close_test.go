package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestServerCloseCancelsContextAndDrainsArchiveWorker pins the teardown contract
// of Server.Close: the server-wide context is cancelled (engine task loops and
// deadline coordinators wind down through it) and the task-archive worker — the
// goroutine that kept polling a closed database and writing into the test's
// temp dir after the test finished — has fully drained when Close returns.
func TestServerCloseCancelsContextAndDrainsArchiveWorker(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	if s.ctx.Err() != nil {
		t.Fatal("server context must be live before Close")
	}
	s.Close()

	if s.ctx.Err() == nil {
		t.Fatal("Close must cancel the server-wide context")
	}
	drained := make(chan struct{})
	go func() {
		s.archiveWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("task-archive worker still running after Close — worker drain is broken")
	}
	// Close is idempotent: a second call (e.g. t.Cleanup after an explicit
	// Close in the test body) must not hang or panic.
	s.Close()
}

// TestServerCloseLeavesQueuedArchiveJobAlone verifies the drained worker really
// stopped consuming: a job queued right before Close stays queued, so nothing
// writes into the (already removed) task directory or a closed database
// afterwards.
func TestServerCloseLeavesQueuedArchiveJobAlone(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(s.Close)

	tsk, err := m.CreateTaskWithOptions("close-drain", "close-drain goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(tsk.ID, 10, 64)
	// QueueTaskArchive only accepts paused/terminal tasks; finish it directly.
	if _, err := m.pg.Exec(`UPDATE tasks SET status='done' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.QueueTaskArchive(taskID); err != nil {
		t.Skipf("archive queue unavailable (%v)", err)
	}
	s.Close()
	time.Sleep(2 * taskArchivePollInterval)
	// The drained worker must not have claimed the job: it is still queued.
	arch, err := m.pg.GetTaskArchiveByTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if arch == nil || arch.State != db.ArchiveQueued {
		t.Fatalf("queued archive job was touched after Close — the worker did not stop: %+v", arch)
	}
}

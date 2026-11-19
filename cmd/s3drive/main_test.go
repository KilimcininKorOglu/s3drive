package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAged(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// Spool cleanup removes stale files only, and never reaches outside the spool
// through a symlinked directory planted inside it.
func TestCleanupSpoolStaysInsideSpool(t *testing.T) {
	base := t.TempDir()
	spool := filepath.Join(base, "spool")
	outside := filepath.Join(base, "outside")
	stale := filepath.Join(spool, "uploads", "stale")
	fresh := filepath.Join(spool, "fresh")
	victim := filepath.Join(outside, "victim")
	writeAged(t, stale, 48*time.Hour)
	writeAged(t, fresh, time.Minute)
	writeAged(t, victim, 48*time.Hour)
	if err := os.Symlink(outside, filepath.Join(spool, "link")); err != nil {
		t.Fatal(err)
	}

	cleanupSpool(spool, 24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale spool file still exists (err=%v)", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh spool file removed: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("file outside the spool removed through symlink: %v", err)
	}
}

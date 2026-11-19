package s3

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"s3drive/internal/drive"
)

func limitServer(limit int64) *Server {
	return &Server{
		Svc: &drive.Service{MaxObjectBytes: limit},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func limitOp() (*opCtx, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/b/k?partNumber=2&uploadId=u", nil)
	return &opCtx{w: &statusWriter{ResponseWriter: rec}, r: req}, rec
}

// The object size limit must hold even when the staged parts cannot be
// measured: an unreadable staging directory rejects the part instead of
// letting it through unchecked.
func TestStagedLimitRejectsWhenPartsCannotBeMeasured(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, rec := limitOp()
	if !limitServer(100).stagedLimitExceeded(o, notADir, 2, 1) {
		t.Fatal("part accepted although staged size could not be measured")
	}
	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx error", rec.Code)
	}
}

func TestStagedLimitCountsStagedParts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "1"), make([]byte, 60), 0o600); err != nil {
		t.Fatal(err)
	}
	o, rec := limitOp()
	if !limitServer(100).stagedLimitExceeded(o, dir, 2, 50) {
		t.Fatal("60 staged + 50 incoming bytes accepted under a 100-byte limit")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	o, _ = limitOp()
	if limitServer(100).stagedLimitExceeded(o, dir, 2, 40) {
		t.Fatal("60 staged + 40 incoming bytes rejected under a 100-byte limit")
	}
	o, _ = limitOp()
	if limitServer(100).stagedLimitExceeded(o, dir, 1, 100) {
		t.Fatal("replacing part 1 must not count its old size")
	}
}

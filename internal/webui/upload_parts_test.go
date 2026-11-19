package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"s3drive/internal/drive"
)

func stage(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A console upload completes only when parts 1..n are all staged; temp
// files are not parts.
func TestWebUploadParts(t *testing.T) {
	dir := t.TempDir()
	stage(t, dir, "1", "2", "part-123", "combined-9")
	if paths, missing := webUploadParts(dir); len(paths) != 2 || missing != 0 {
		t.Fatalf("contiguous: %d parts, missing %d; want 2, 0", len(paths), missing)
	}
	stage(t, dir, "4")
	if paths, missing := webUploadParts(dir); len(paths) != 3 || missing != 3 {
		t.Fatalf("gap: %d parts, missing %d; want 3, 3", len(paths), missing)
	}
	gapFirst := t.TempDir()
	stage(t, gapFirst, "2")
	if _, missing := webUploadParts(gapFirst); missing != 1 {
		t.Fatalf("missing first part: got %d, want 1", missing)
	}
	if paths, _ := webUploadParts(filepath.Join(dir, "absent")); len(paths) != 0 {
		t.Fatalf("absent dir: got %d parts", len(paths))
	}
}

// The declared size from the browser is untrusted: a malformed or negative
// value is refused, and the part size keeps the upload within 10,000 parts.
func TestUploadPlan(t *testing.T) {
	s := &Server{Svc: &drive.Service{}}
	for _, raw := range []string{"abc", "-1", "1e9"} {
		if _, _, msg, status := s.uploadPlan(raw); msg == "" || status != http.StatusBadRequest {
			t.Errorf("size %q accepted (status %d)", raw, status)
		}
	}
	if _, part, msg, _ := s.uploadPlan(""); msg != "" || part != uiMinPartSize {
		t.Errorf("unknown size: part %d, msg %q", part, msg)
	}
	size := int64(200 << 30) // 200 GiB needs parts above the minimum
	_, part, msg, _ := s.uploadPlan("214748364800")
	if msg != "" || part*uiPartCount < size || part < uiMinPartSize {
		t.Errorf("200 GiB: part %d, msg %q", part, msg)
	}
	if _, _, msg, status := s.uploadPlan("20000000000000"); msg == "" || status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized object accepted (status %d)", status)
	}
	s.Svc.MaxObjectBytes = 10
	if _, _, msg, status := s.uploadPlan("11"); msg == "" || status != http.StatusRequestEntityTooLarge {
		t.Errorf("object limit not enforced (status %d)", status)
	}
}

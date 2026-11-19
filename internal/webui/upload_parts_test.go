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
	const gib200 = int64(200 << 30) // needs parts above the minimum
	cases := []struct {
		raw      string
		limit    int64
		status   int   // 0: accepted
		minParts int64 // accepted: part size must cover the size in 10,000 parts
	}{
		{raw: "abc", status: http.StatusBadRequest},
		{raw: "-1", status: http.StatusBadRequest},
		{raw: "1e9", status: http.StatusBadRequest},
		{raw: "", minParts: 0},
		{raw: "214748364800", minParts: gib200},
		{raw: "20000000000000", status: http.StatusRequestEntityTooLarge},
		{raw: "11", limit: 10, status: http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		s := &Server{Svc: &drive.Service{MaxObjectBytes: c.limit}}
		_, part, msg, status := s.uploadPlan(c.raw)
		if status != c.status || (c.status != 0) != (msg != "") {
			t.Errorf("size %q: status %d msg %q, want status %d", c.raw, status, msg, c.status)
			continue
		}
		if c.status == 0 && (part < uiMinPartSize || part*uiPartCount < c.minParts) {
			t.Errorf("size %q: part size %d too small", c.raw, part)
		}
	}
}

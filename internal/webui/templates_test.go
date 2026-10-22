package webui

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"s3drive/internal/config"
	"s3drive/internal/drive"
	"s3drive/internal/google"
	"s3drive/internal/secure"
	"s3drive/internal/store"
)

func TestTemplatesParseAndLoginRenders(t *testing.T) {
	dir := t.TempDir()
	box, err := secure.New(dir, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	spool := filepath.Join(dir, "tmp")
	svc := drive.New(st, google.NewClient(st), spool, "http://localhost:8080", logger)
	srv, err := New(config.Config{
		DataDir: dir, SpoolDir: spool, PublicURL: "http://localhost:8080",
		UIPassword: "test-password", MaxUIBodyBytes: 1 << 20,
	}, st, svc, google.NewClient(st), logger)
	if err != nil {
		t.Fatalf("template parse: %v", err)
	}

	for _, lang := range []string{"en", "tr"} {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.AddCookie(&http.Cookie{Name: "lang", Value: lang})
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s login status = %d: %s", lang, rec.Code, rec.Body.String())
		}
		if len(rec.Body.Bytes()) < 500 {
			t.Fatalf("%s login page too small", lang)
		}
	}
}

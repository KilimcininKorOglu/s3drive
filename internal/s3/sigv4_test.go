package s3

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"s3drive/internal/secure"
	"s3drive/internal/store"
)

func sigTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	box, err := secure.New(dir, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateAccessKey(context.Background(), &store.AccessKey{
		AccessKey: "S3DTEST", Secret: "secret", Label: "test", Active: true, Permission: "rw",
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPresignedGetAndPutVerify(t *testing.T) {
	st := sigTestStore(t)
	auth := &Authenticator{Store: st}
	expires := time.Now().Add(10 * time.Minute)

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		raw := "http://example.test/photos/2026/caf%C3%A9+men%C3%BC.txt"
		signed, err := SignQueryMethod(raw, "S3DTEST", "secret", "us-east-1", method, expires)
		if err != nil {
			t.Fatalf("%s sign: %v", method, err)
		}
		req, err := http.NewRequest(method, signed, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, aerr := auth.Authenticate(req)
		if aerr != nil {
			t.Fatalf("%s verify: %v (%s)", method, aerr, signed)
		}
		if !got.Presigned || got.AccessKey != "S3DTEST" {
			t.Fatalf("%s auth = %+v", method, got)
		}
	}
}

func TestPresignedRejectsTamperedPathAndDisabledKey(t *testing.T) {
	st := sigTestStore(t)
	auth := &Authenticator{Store: st}
	signed, err := SignQuery("http://example.test/photos/a.txt", "S3DTEST", "secret", "us-east-1", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, signed+"x", nil)
	if _, aerr := auth.Authenticate(req); aerr == nil {
		t.Fatal("tampered path verified")
	}

	if err := st.SetAccessKeyActive(context.Background(), "S3DTEST", false); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, signed, nil)
	if _, aerr := auth.Authenticate(req); aerr == nil {
		t.Fatal("disabled key verified")
	}
}

func TestPresignedLongExpiryUsesCreationTime(t *testing.T) {
	st := sigTestStore(t)
	auth := &Authenticator{Store: st}
	signed, err := SignQuery("http://example.test/photos/a.txt", "S3DTEST", "secret", "us-east-1", time.Now().Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, signed, nil)
	if _, aerr := auth.Authenticate(req); aerr != nil {
		t.Fatalf("long presigned URL rejected: %v (%s)", aerr, signed)
	}
}

func TestPresignedQueryPreservesLiteralPlusAndPercentEscapes(t *testing.T) {
	st := sigTestStore(t)
	auth := &Authenticator{Store: st}
	raw := "http://example.test/b/k?x=a+b&y=c%2Fd&z=%C3%BC"
	signed, err := SignQueryMethod(raw, "S3DTEST", "secret", "us-east-1", http.MethodGet, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, signed, nil)
	if _, aerr := auth.Authenticate(req); aerr != nil {
		t.Fatalf("verify: %v (%s)", aerr, signed)
	}
	if !strings.Contains(signed, "x=a+b") || !strings.Contains(signed, "y=c%2Fd") {
		t.Fatalf("query was rewritten: %s", signed)
	}
}

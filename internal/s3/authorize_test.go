package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"s3drive/internal/store"
)

type authCase struct {
	name, method, target string
	bucket, key          string
	allow                bool
	wantPrefix           string // prefix query expected after authorize, "" to skip
}

func runAuthCase(t *testing.T, k *store.AccessKey, c authCase) {
	t.Helper()
	rec := httptest.NewRecorder()
	o := &opCtx{w: &statusWriter{ResponseWriter: rec}, r: httptest.NewRequest(c.method, c.target, nil), bucket: c.bucket, key: c.key}
	got := (&Server{}).authorize(o, &Auth{Key: k})
	if got != c.allow {
		t.Fatalf("%s: authorize = %v, want %v", c.name, got, c.allow)
	}
	if !c.allow && c.bucket != "" && rec.Code != http.StatusForbidden && rec.Code != http.StatusOK {
		t.Fatalf("%s: status = %d", c.name, rec.Code)
	}
	if c.wantPrefix != "" && o.r.URL.Query().Get("prefix") != c.wantPrefix {
		t.Fatalf("%s: prefix = %q, want %q", c.name, o.r.URL.Query().Get("prefix"), c.wantPrefix)
	}
}

// A read-only key scoped to photos/2026/ must never act outside that scope,
// and bucket listings are narrowed to its prefix.
func TestAuthorizeScopedReadOnlyKey(t *testing.T) {
	k := &store.AccessKey{AccessKey: "K", Active: true, Permission: "ro", Bucket: "photos", Prefix: "2026/"}
	cases := []authCase{
		{"list buckets", http.MethodGet, "/", "", "", true, ""},
		{"create bucket at root", http.MethodPut, "/", "", "", false, ""},
		{"list scoped bucket injects prefix", http.MethodGet, "/photos?list-type=2", "photos", "", true, "2026/"},
		{"list with prefix inside scope", http.MethodGet, "/photos?prefix=2026/x", "photos", "", true, "2026/x"},
		{"list with prefix outside scope", http.MethodGet, "/photos?prefix=2025/", "photos", "", false, ""},
		{"list other bucket", http.MethodGet, "/other", "other", "", false, ""},
		{"delete bucket", http.MethodDelete, "/photos", "photos", "", false, ""},
		{"create bucket", http.MethodPut, "/photos", "photos", "", false, ""},
		{"multi-delete in scope bucket", http.MethodPost, "/photos?delete", "photos", "", true, ""},
		{"multi-delete other bucket", http.MethodPost, "/other?delete", "other", "", false, ""},
		{"other bucket POST", http.MethodPost, "/photos", "photos", "", false, ""},
		{"read in scope", http.MethodGet, "/photos/2026/a.jpg", "photos", "2026/a.jpg", true, ""},
		{"head in scope", http.MethodHead, "/photos/2026/a.jpg", "photos", "2026/a.jpg", true, ""},
		{"read outside prefix", http.MethodGet, "/photos/2025/a.jpg", "photos", "2025/a.jpg", false, ""},
		{"write in scope", http.MethodPut, "/photos/2026/a.jpg", "photos", "2026/a.jpg", false, ""},
	}
	for _, c := range cases {
		runAuthCase(t, k, c)
	}
}

func TestAuthorizeReadWriteKey(t *testing.T) {
	k := &store.AccessKey{AccessKey: "K", Active: true, Permission: "rw", Bucket: "photos"}
	cases := []authCase{
		{"write object", http.MethodPut, "/photos/a.jpg", "photos", "a.jpg", true, ""},
		{"delete object", http.MethodDelete, "/photos/a.jpg", "photos", "a.jpg", true, ""},
		{"write other bucket", http.MethodPut, "/other/a.jpg", "other", "a.jpg", false, ""},
		{"create own bucket", http.MethodPut, "/photos", "photos", "", true, ""},
		{"create other bucket", http.MethodPut, "/other", "other", "", false, ""},
	}
	for _, c := range cases {
		runAuthCase(t, k, c)
	}
	if !(&Server{}).authorize(&opCtx{r: httptest.NewRequest(http.MethodPut, "/x", nil), bucket: "x"}, &Auth{}) {
		t.Fatal("a request without a key policy (root credentials) must be allowed")
	}
}

package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"s3drive/internal/store"
)

// x-amz-copy-source is client input: a key scoped to photos/2026/ must not
// read any other object through CopyObject or UploadPartCopy, and a
// ?versionId suffix does not change the source key.
func TestCopySourceEnforcesKeyPolicy(t *testing.T) {
	k := &store.AccessKey{AccessKey: "K", Active: true, Permission: "rw", Bucket: "photos", Prefix: "2026/"}
	cases := []struct {
		header      string
		ok          bool
		status      int
		bucket, key string
	}{
		{"/photos/2026/a.jpg", true, 0, "photos", "2026/a.jpg"},
		{"photos/2026/a%20b.jpg?versionId=3", true, 0, "photos", "2026/a b.jpg"},
		{"/photos/2025/a.jpg", false, http.StatusForbidden, "", ""},
		{"/secrets/2026/a.jpg", false, http.StatusForbidden, "", ""},
		// S3 keys are literal and Drive stores ".." as an escaped name, so
		// this stays inside 2026/ rather than reaching 2025/.
		{"/photos/2026%2F..%2F2025/a.jpg", true, 0, "photos", "2026/../2025/a.jpg"},
		{"/photos", false, http.StatusBadRequest, "", ""},
		{"/photos/%zz", false, http.StatusBadRequest, "", ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPut, "/photos/2026/dst", nil)
		r.Header.Set("x-amz-copy-source", c.header)
		o := &opCtx{w: &statusWriter{ResponseWriter: rec}, r: r, keyPolicy: k}
		bucket, key, ok := copySource(o)
		if ok != c.ok || bucket != c.bucket || key != c.key {
			t.Errorf("%q: got %q %q %v, want %q %q %v", c.header, bucket, key, ok, c.bucket, c.key, c.ok)
		}
		if !c.ok && rec.Code != c.status {
			t.Errorf("%q: status %d, want %d", c.header, rec.Code, c.status)
		}
	}
}

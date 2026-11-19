package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Byte ranges per RFC 9110 section 14.1.2: first-last (inclusive, last
// clamped to the size), first- (to the end), -suffix (last N bytes, clamped);
// unsatisfiable or malformed ranges are rejected. Multiple ranges are not
// supported here.
func TestParseByteRange(t *testing.T) {
	const size = 100
	cases := []struct {
		in                 string
		start, end, length int64
		ok                 bool
	}{
		{"bytes=0-9", 0, 9, 10, true},
		{"bytes=10-", 10, 99, 90, true},
		{"bytes=90-200", 90, 99, 10, true},
		{"bytes=-10", 90, 99, 10, true},
		{"bytes=-500", 0, 99, 100, true},
		{"bytes= 5-6", 5, 6, 2, true},
		{"bytes=100-", 0, 0, 0, false},
		{"bytes=9-5", 0, 0, 0, false},
		{"bytes=-0", 0, 0, 0, false},
		{"bytes=0-1,5-6", 0, 0, 0, false},
		{"bytes=abc", 0, 0, 0, false},
		{"bytes=a-5", 0, 0, 0, false},
		{"items=0-1", 0, 0, 0, false},
		{"bytes=-x", 0, 0, 0, false},
	}
	for _, c := range cases {
		s, e, l, ok := parseByteRange(c.in, size)
		if ok != c.ok || (ok && (s != c.start || e != c.end || l != c.length)) {
			t.Errorf("parseByteRange(%q) = %d,%d,%d,%v want %d,%d,%d,%v", c.in, s, e, l, ok, c.start, c.end, c.length, c.ok)
		}
	}
	if _, _, _, ok := parseByteRange("bytes=-5", 0); ok {
		t.Error("suffix range on an empty object must be unsatisfiable")
	}
}

// Operation names follow the AWS S3 API action names.
func TestOpName(t *testing.T) {
	req := func(method, target string, copySource bool) *http.Request {
		r := httptest.NewRequest(method, target, nil)
		if copySource {
			r.Header.Set("x-amz-copy-source", "/src/k")
		}
		return r
	}
	cases := []struct {
		r           *http.Request
		bucket, key string
		want        string
	}{
		{req(http.MethodGet, "/", false), "", "", "ListBuckets"},
		{req(http.MethodPut, "/b", false), "b", "", "CreateBucket"},
		{req(http.MethodDelete, "/b", false), "b", "", "DeleteBucket"},
		{req(http.MethodHead, "/b", false), "b", "", "HeadBucket"},
		{req(http.MethodPost, "/b?delete", false), "b", "", "DeleteObjects"},
		{req(http.MethodPost, "/b", false), "b", "", "Post"},
		{req(http.MethodGet, "/b?location", false), "b", "", "GetBucketLocation"},
		{req(http.MethodGet, "/b?uploads", false), "b", "", "ListMultipartUploads"},
		{req(http.MethodGet, "/b", false), "b", "", "ListObjects"},
		{req(http.MethodPatch, "/b", false), "b", "", ""},
		{req(http.MethodPut, "/b/k", true), "b", "k", "CopyObject"},
		{req(http.MethodPut, "/b/k?uploadId=u&partNumber=1", false), "b", "k", "UploadPart"},
		{req(http.MethodPut, "/b/k", false), "b", "k", "PutObject"},
		{req(http.MethodPost, "/b/k?uploads", false), "b", "k", "CreateMultipartUpload"},
		{req(http.MethodPost, "/b/k?uploadId=u", false), "b", "k", "CompleteMultipartUpload"},
		{req(http.MethodPost, "/b/k", false), "b", "k", "PostObject"},
		{req(http.MethodGet, "/b/k?uploadId=u", false), "b", "k", "ListParts"},
		{req(http.MethodGet, "/b/k", false), "b", "k", "GetObject"},
		{req(http.MethodHead, "/b/k", false), "b", "k", "HeadObject"},
		{req(http.MethodDelete, "/b/k?uploadId=u", false), "b", "k", "AbortMultipartUpload"},
		{req(http.MethodDelete, "/b/k", false), "b", "k", "DeleteObject"},
		{req(http.MethodPatch, "/b/k", false), "b", "k", ""},
	}
	for _, c := range cases {
		if got := opName(c.r, c.bucket, c.key); got != c.want {
			t.Errorf("opName(%s %s) = %q, want %q", c.r.Method, c.r.URL, got, c.want)
		}
	}
}

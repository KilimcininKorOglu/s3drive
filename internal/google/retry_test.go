package google

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"s3drive/internal/store"
)

// flakyServer answers 503 for the first failures requests, then 200.
func flakyServer(t *testing.T, failures int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= failures {
			http.Error(w, `{"error":{"code":503,"message":"backend error"}}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func testClient(srv *httptest.Server) (*Client, *store.Account) {
	c := &Client{HTTP: srv.Client(), tokens: map[string]*tokenState{}}
	// A valid cached token keeps AccessToken off the network.
	acct := &store.Account{ID: "a1", AccessToken: "tok", TokenExpiry: time.Now().Add(time.Hour)}
	return c, acct
}

// AGENTS.md: only GET/HEAD/DELETE may be retried; POST and PATCH must never
// be sent twice, or Drive may create duplicate files.
func TestDoNeverRetriesNonIdempotentMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut} {
		srv, calls := flakyServer(t, 1)
		c, acct := testClient(srv)
		_, err := c.do(context.Background(), acct, method, srv.URL, strings.NewReader("{}"), nil)
		if err == nil {
			t.Errorf("%s: got success after a 503, want the 503 error", method)
		}
		if n := calls.Load(); n != 1 {
			t.Errorf("%s: sent %d times, want exactly 1", method, n)
		}
	}
}

// Resumable upload protocol: a 308 with "Range: bytes=0-N" means N+1 bytes
// were stored; 404/410 means the session is gone; 5xx is retried.
func TestQueryResumable(t *testing.T) {
	cases := []struct {
		name       string
		statuses   []int
		rangeHdr   string
		wantOffset int64
		wantGone   bool
		wantCalls  int32
	}{
		{name: "partial", statuses: []int{308}, rangeHdr: "bytes=0-99", wantOffset: 100, wantCalls: 1},
		{name: "nothing stored", statuses: []int{308}, wantOffset: 0, wantCalls: 1},
		{name: "gone", statuses: []int{http.StatusNotFound}, wantGone: true, wantCalls: 1},
		{name: "retry 5xx", statuses: []int{503, 308}, rangeHdr: "bytes=0-9", wantOffset: 10, wantCalls: 2},
	}
	for _, tc := range cases {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i := int(calls.Add(1)) - 1
			if r.Header.Get("Content-Range") != "bytes */500" {
				t.Errorf("%s: Content-Range %q", tc.name, r.Header.Get("Content-Range"))
			}
			if tc.rangeHdr != "" {
				w.Header().Set("Range", tc.rangeHdr)
			}
			w.WriteHeader(tc.statuses[min(i, len(tc.statuses)-1)])
		}))
		c, acct := testClient(srv)
		offset, file, err := c.queryResumable(context.Background(), acct, srv.URL, 500)
		srv.Close()
		if tc.wantGone != errors.Is(err, errResumeGone) || (!tc.wantGone && err != nil) {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if offset != tc.wantOffset || file != nil || calls.Load() != tc.wantCalls {
			t.Errorf("%s: offset %d file %v calls %d, want %d nil %d", tc.name, offset, file, calls.Load(), tc.wantOffset, tc.wantCalls)
		}
	}
}

// A 308 after a chunk: Drive's Range header names the bytes it stored, which
// can be fewer than were sent; no header means the whole chunk was stored.
func TestNextOffset(t *testing.T) {
	cases := []struct {
		hdr       string
		offset, n int64
		want      int64
	}{
		{"bytes=0-149", 100, 100, 150}, // partial chunk stored
		{"bytes=0-199", 100, 100, 200}, // whole chunk stored
		{"", 100, 100, 200},            // no header
		{"bytes=0-49", 100, 100, 200},  // stale header behind offset
	}
	for _, c := range cases {
		if got := nextOffset(c.hdr, c.offset, c.n); got != c.want {
			t.Errorf("nextOffset(%q, %d, %d) = %d, want %d", c.hdr, c.offset, c.n, got, c.want)
		}
	}
}

func TestDoRetriesIdempotentMethodsAfter5xx(t *testing.T) {
	srv, calls := flakyServer(t, 1)
	c, acct := testClient(srv)
	resp, err := c.do(context.Background(), acct, http.MethodGet, srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("GET after one 503: %v", err)
	}
	_ = resp.Body.Close()
	if n := calls.Load(); n != 2 {
		t.Fatalf("GET sent %d times, want 2", n)
	}
}

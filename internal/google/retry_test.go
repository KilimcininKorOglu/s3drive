package google

import (
	"context"
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

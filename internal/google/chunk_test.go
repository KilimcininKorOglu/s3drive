package google

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"s3drive/internal/secure"
	"s3drive/internal/store"
)

// handlerTransport serves every request, including the Google token
// endpoint, from a local handler so the test never reaches the network.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func storeWithAccount(t *testing.T) (*store.Store, *store.Account) {
	t.Helper()
	dir := t.TempDir()
	box, err := secure.New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	acct := &store.Account{
		Name: "test", Email: "user@example.com", ClientID: "cid", ClientSecret: "csecret",
		RefreshToken: "refresh", AccessToken: "tok", TokenExpiry: time.Now().Add(time.Hour),
	}
	if err := st.CreateAccount(context.Background(), acct); err != nil {
		t.Fatal(err)
	}
	return st, acct
}

// A chunk that Drive keeps rejecting with 401, even after successful token
// refreshes, must fail the upload. Sending the following chunk instead would
// put its bytes at the rejected chunk's offset and corrupt the object.
func TestPutResumableChunksStopsWhenAChunkIsNeverAccepted(t *testing.T) {
	st, acct := storeWithAccount(t)
	var mu sync.Mutex
	var puts []string // "<Content-Range> <first body byte>"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Host, "oauth2.googleapis.com") {
			_, _ = io.WriteString(w, `{"access_token":"fresh","expires_in":3600}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		puts = append(puts, r.Header.Get("Content-Range")+" "+string(body[:1]))
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := &Client{Store: st, HTTP: &http.Client{Transport: handlerTransport{h}}, tokens: map[string]*tokenState{}}

	// Two full chunks, so a wrongly advanced reader can fill the next one.
	size := int64(2 * chunkSize)
	data := append(bytes.Repeat([]byte("a"), chunkSize), bytes.Repeat([]byte("b"), chunkSize)...)
	file, _, err := c.putResumableChunks(context.Background(), acct, "https://upload.example.com/session",
		bytes.NewReader(data), size, 0, nil)
	if err == nil || file != nil {
		t.Fatalf("got file %v, err %v; want an error", file, err)
	}
	for _, p := range puts {
		if !strings.HasSuffix(p, " a") {
			t.Fatalf("sent %q: bytes of the second chunk went to the first chunk's range", p)
		}
	}
	if len(puts) != 6 {
		t.Fatalf("sent %d chunk requests, want 6 attempts of the first chunk", len(puts))
	}
}

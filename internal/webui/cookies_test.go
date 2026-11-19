package webui

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// httpsRequest simulates a console request served over TLS.
func httpsRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.TLS = &tls.ConnectionState{}
	return req
}

func findCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not set", name)
	return nil
}

// The flash cookie can carry a new S3 secret key, so over HTTPS it must never
// be sent on a plain HTTP request.
func TestFlashCookieIsSecureOverHTTPS(t *testing.T) {
	s := &Server{}
	req := httpsRequest(http.MethodPost, "/keys")
	rec := httptest.NewRecorder()
	s.setFlashSecret(rec, req, "ok", "created", "AKIA  /  secret")
	c := findCookie(t, rec, "s3drive_flash")
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flash cookie Secure=%v HttpOnly=%v SameSite=%v, want true/true/Lax", c.Secure, c.HttpOnly, c.SameSite)
	}

	read := httpsRequest(http.MethodGet, "/")
	read.AddCookie(&http.Cookie{Name: "s3drive_flash", Value: c.Value})
	rec = httptest.NewRecorder()
	if f := s.popFlash(rec, read); f == nil || f.Secret != "AKIA  /  secret" {
		t.Fatalf("popFlash = %+v, want the stored secret", f)
	}
	del := findCookie(t, rec, "s3drive_flash")
	if del.MaxAge >= 0 || !del.Secure || !del.HttpOnly || del.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flash delete cookie MaxAge=%d Secure=%v HttpOnly=%v SameSite=%v", del.MaxAge, del.Secure, del.HttpOnly, del.SameSite)
	}
}

func TestFlashCookieNotSecureOverPlainHTTP(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.setFlash(rec, httptest.NewRequest(http.MethodPost, "/keys", nil), "ok", "done")
	if findCookie(t, rec, "s3drive_flash").Secure {
		t.Fatal("flash cookie is Secure on plain HTTP; the browser would drop it")
	}
}

func TestLangCookieIsHttpOnly(t *testing.T) {
	s := &Server{}
	req := httpsRequest(http.MethodPost, "/lang")
	req.Body = http.NoBody
	req.Form = map[string][]string{"lang": {"tr"}}
	rec := httptest.NewRecorder()
	s.setLang(rec, req)
	c := findCookie(t, rec, "lang")
	if !c.HttpOnly || !c.Secure || !strings.EqualFold(c.Value, "tr") {
		t.Fatalf("lang cookie HttpOnly=%v Secure=%v Value=%q", c.HttpOnly, c.Secure, c.Value)
	}
}

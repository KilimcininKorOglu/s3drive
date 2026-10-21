// Package webui serves the htmx admin console.
package webui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"s3drive/internal/config"
	"s3drive/internal/drive"
	"s3drive/internal/google"
	"s3drive/internal/store"
	webassets "s3drive/web"
)

// Server is the web console.
type Server struct {
	Cfg    config.Config
	Store  *store.Store
	Svc    *drive.Service
	Google *google.Client
	Log    *slog.Logger

	mux        *http.ServeMux
	sessionKey []byte
	templates  map[string]map[string]*template.Template
	partials   map[string]*template.Template
}

var pageNames = []string{"dashboard", "files", "buckets", "accounts", "keys", "settings", "login"}

// New builds the console and parses every template for every language.
func New(cfg config.Config, st *store.Store, svc *drive.Service, g *google.Client, log *slog.Logger) (*Server, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	s := &Server{
		Cfg: cfg, Store: st, Svc: svc, Google: g, Log: log, sessionKey: key,
		mux:       http.NewServeMux(),
		templates: map[string]map[string]*template.Template{},
		partials:  map[string]*template.Template{},
	}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) loadTemplates() error {
	for code := range langs {
		l := language(code)
		s.templates[code] = map[string]*template.Template{}
		for _, page := range pageNames {
			t, err := template.New("layout").Funcs(templateFuncs(l)).ParseFS(webassets.FS,
				"templates/layout.html", "templates/partials.html", "templates/"+page+".html")
			if err != nil {
				return fmt.Errorf("parse %s/%s: %w", code, page, err)
			}
			s.templates[code][page] = t
		}
		pt, err := template.New("partials").Funcs(templateFuncs(l)).ParseFS(webassets.FS, "templates/partials.html")
		if err != nil {
			return fmt.Errorf("parse partials %s: %w", code, err)
		}
		s.partials[code] = pt
	}
	return nil
}

func templateFuncs(l *lang) template.FuncMap {
	return template.FuncMap{
		"t":        l.t,
		"bytes":    humanBytes,
		"initial":  initial,
		"date":     func(t time.Time) string { return formatDate(t, l.date) },
		"datetime": func(t time.Time) string { return formatDate(t, l.dateTime) },
	}
}

func formatDate(t time.Time, layout string) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format(layout)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func initial(name string) string {
	for _, r := range strings.TrimSpace(name) {
		return string(unicode.ToUpper(r))
	}
	return "?"
}

func (s *Server) routes() {
	mux := s.mux
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /partials/dashboard", s.dashboardPartial)

	mux.HandleFunc("GET /files", s.files)
	mux.HandleFunc("GET /files/download", s.download)
	mux.HandleFunc("POST /files/upload", s.upload)
	mux.HandleFunc("POST /files/folder", s.createFolder)
	mux.HandleFunc("POST /files/delete", s.deleteObject)

	mux.HandleFunc("GET /buckets", s.buckets)
	mux.HandleFunc("POST /buckets/create", s.createBucket)
	mux.HandleFunc("POST /buckets/delete", s.deleteBucket)
	mux.HandleFunc("POST /buckets/public", s.togglePublic)

	mux.HandleFunc("GET /accounts", s.accounts)
	mux.HandleFunc("POST /accounts/delete", s.deleteAccount)
	mux.HandleFunc("GET /oauth/start", s.oauthStart)
	mux.HandleFunc("GET /oauth/callback", s.oauthCallback)

	mux.HandleFunc("GET /keys", s.keys)
	mux.HandleFunc("POST /keys/create", s.createKey)
	mux.HandleFunc("POST /keys/toggle", s.toggleKey)
	mux.HandleFunc("POST /keys/delete", s.deleteKey)

	mux.HandleFunc("GET /settings", s.settings)
	mux.HandleFunc("POST /settings/oauth", s.saveOAuthSettings)
	mux.HandleFunc("POST /settings/server", s.saveServerSettings)

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /lang", s.setLang)
	mux.HandleFunc("GET /healthz", s.health)

	sub, _ := fs.Sub(webassets.FS, "static")
	files := http.FileServer(http.FS(sub))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	})))
}

// ServeHTTP applies security headers, authentication and CSRF checks.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'")

	path := r.URL.Path
	public := path == "/login" || path == "/lang" || path == "/healthz" ||
		strings.HasPrefix(path, "/static/") || path == "/oauth/callback"

	if !public && !s.isAuthed(r) {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+urlQuery(next), http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		if !s.checkCSRF(r) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) isAuthed(r *http.Request) bool {
	if s.Cfg.UIPassword == "" {
		return true
	}
	c, err := r.Cookie("s3drive_session")
	if err != nil {
		return false
	}
	expiryPart, sigPart, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(expiryPart))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sigPart)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(expiryPart, 10, 64)
	return err == nil && time.Now().Unix() < exp
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request) {
	expiry := time.Now().Add(s.Cfg.SessionTTL).Unix()
	payload := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(payload))
	http.SetCookie(w, &http.Cookie{
		Name:     "s3drive_session",
		Value:    payload + "." + hex.EncodeToString(mac.Sum(nil)),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie(r),
		MaxAge:   int(s.Cfg.SessionTTL.Seconds()),
	})
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "s3drive_session", Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.secureCookie(r), MaxAge: -1,
	})
}

func (s *Server) secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.Cfg.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("s3drive_csrf"); err == nil && len(c.Value) >= 24 {
		return c.Value
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     "s3drive_csrf",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie(r),
		MaxAge:   12 * 60 * 60,
	})
	return token
}

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie("s3drive_csrf")
	if err != nil || c.Value == "" {
		return false
	}
	token := r.FormValue("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) == 1
}

// ---------------------------------------------------------------------------
// Page data and rendering

type flashMessage struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Secret string `json:"secret,omitempty"`
}

type baseData struct {
	Lang        string
	SiteName    string
	Title       string
	Subtitle    string
	Nav         string
	Version     string
	CSRF        string
	Flash       *flashMessage
	PasswordSet bool
	AuthPage    bool
	Health      string
	HealthWarn  bool
}

func (s *Server) base(w http.ResponseWriter, r *http.Request, title, subtitle, nav string, withFlash bool) baseData {
	l := s.langFor(r)
	b := baseData{
		Lang:        l.code,
		SiteName:    s.siteName(r),
		Title:       title,
		Subtitle:    subtitle,
		Nav:         nav,
		Version:     config.Version,
		CSRF:        s.csrfToken(w, r),
		PasswordSet: s.Cfg.UIPassword != "",
	}
	if withFlash {
		b.Flash = s.popFlash(w, r)
	}
	accounts, err := s.Store.ListAccounts(r.Context())
	if err == nil {
		switch {
		case len(accounts) == 0:
			b.Health, b.HealthWarn = l.t("health.no_accounts"), true
		default:
			reauth := false
			for _, a := range accounts {
				if a.NeedsReauth {
					reauth = true
					break
				}
			}
			if reauth {
				b.Health, b.HealthWarn = l.t("health.reauth"), true
			} else {
				b.Health, b.HealthWarn = l.t("health.ok"), false
			}
		}
	}
	return b
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	l := s.langFor(r)
	tmpl, ok := s.templates[l.code][page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.Log.Error("render page", "page", page, "err", err)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, r *http.Request, name string, data any) {
	l := s.langFor(r)
	tmpl, ok := s.partials[l.code]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.Log.Error("render partial", "name", name, "err", err)
	}
}

func (s *Server) t(r *http.Request) *lang { return s.langFor(r) }

func (s *Server) langFor(r *http.Request) *lang {
	if c, err := r.Cookie("lang"); err == nil {
		if _, ok := langs[strings.ToLower(c.Value)]; ok {
			return language(c.Value)
		}
	}
	header := r.Header.Get("Accept-Language")
	if strings.HasPrefix(strings.ToLower(header), "tr") || strings.Contains(strings.ToLower(header), ",tr") {
		return tr
	}
	return en
}

func (s *Server) siteName(r *http.Request) string {
	if v, err := s.Store.Setting(r.Context(), drive.SettingSiteName); err == nil && v != "" {
		return v
	}
	return "s3drive"
}

func (s *Server) publicURL(r *http.Request) string {
	if v, err := s.Store.Setting(r.Context(), drive.SettingPublicURL); err == nil && v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(s.Cfg.PublicURL, "/")
}

func (s *Server) oauthReady(r *http.Request) bool {
	cfg, err := s.Google.OAuthConfig(r.Context(), s.publicURL(r))
	return err == nil && cfg.ClientID != "" && cfg.ClientSecret != ""
}

// ---------------------------------------------------------------------------
// Flash messages

func (s *Server) setFlash(w http.ResponseWriter, kind, text string) {
	s.setFlashSecret(w, kind, text, "")
}

func (s *Server) setFlashSecret(w http.ResponseWriter, kind, text, secret string) {
	raw, _ := json.Marshal(flashMessage{Kind: kind, Text: text, Secret: secret})
	http.SetCookie(w, &http.Cookie{
		Name:     "s3drive_flash",
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   120,
	})
}

func (s *Server) popFlash(w http.ResponseWriter, r *http.Request) *flashMessage {
	c, err := r.Cookie("s3drive_flash")
	if err != nil || c.Value == "" {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: "s3drive_flash", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var f flashMessage
	if json.Unmarshal(raw, &f) != nil || f.Text == "" {
		return nil
	}
	if f.Kind == "" {
		f.Kind = "ok"
	}
	return &f
}

func urlQuery(s string) string {
	return strings.ReplaceAll(fmt.Sprintf("%s", urlEscape(s)), "+", "%20")
}

func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == '/' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

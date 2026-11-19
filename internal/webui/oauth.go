package webui

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"s3drive/internal/google"
	"s3drive/internal/store"
)

// flashRedirect stores a one-shot error message and redirects to the page.
func (s *Server) flashRedirect(w http.ResponseWriter, r *http.Request, text, to string) {
	s.setFlash(w, r, "error", text)
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// oauthStart begins the Google consent flow. An optional account id
// re-authorizes an existing account, keeping its buckets and keys.
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	if s.currentRole(r) != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return
	}
	l := s.t(r)
	ctx := r.Context()

	cfg, err := s.Google.OAuthConfig(ctx, s.publicURL(r))
	if err != nil {
		s.flashRedirect(w, r, l.errorText(err), "/accounts")
		return
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		s.flashRedirect(w, r, l.t("flash.oauth_missing"), "/settings")
		return
	}
	accountID := strings.TrimSpace(r.URL.Query().Get("account"))
	loginHint, err := s.reauthTarget(ctx, accountID, &cfg)
	if err != nil {
		s.flashRedirect(w, r, l.errorText(err), "/accounts")
		return
	}
	state, challenge, err := s.newOAuthState(ctx, accountID)
	if err != nil {
		s.flashRedirect(w, r, l.errorText(err), "/accounts")
		return
	}
	http.Redirect(w, r, google.AuthCodeURL(cfg, state, challenge, loginHint), http.StatusSeeOther) // #nosec G710 -- fixed Google auth endpoint; inputs are query-escaped
}

// reauthTarget loads the account being re-authorized, if any. Accounts
// authorized with their own OAuth client keep using it. It returns the
// account email as the login hint.
func (s *Server) reauthTarget(ctx context.Context, accountID string, cfg *google.OAuthConfig) (string, error) {
	if accountID == "" {
		return "", nil
	}
	acct, err := s.Store.GetAccount(ctx, accountID)
	if err != nil {
		return "", err
	}
	useAccountClient(acct, cfg)
	return acct.Email, nil
}

func useAccountClient(acct *store.Account, cfg *google.OAuthConfig) {
	if acct.ClientID != "" && acct.ClientSecret != "" {
		cfg.ClientID, cfg.ClientSecret = acct.ClientID, acct.ClientSecret
	}
}

// newOAuthState stores a fresh state with its PKCE verifier and returns the
// state and the S256 challenge.
func (s *Server) newOAuthState(ctx context.Context, accountID string) (state, challenge string, err error) {
	if state, err = randomState(); err != nil {
		return "", "", err
	}
	verifier, challenge, err := google.NewVerifier()
	if err != nil {
		return "", "", err
	}
	if err := s.Store.CreateOAuthState(ctx, state, verifier, accountID); err != nil {
		return "", "", err
	}
	return state, challenge, nil
}

// oauthCallback validates the state, exchanges the code, stores the refresh
// token and refreshes the account profile.
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	ctx := r.Context()
	q := r.URL.Query()
	if msg := oauthErrorParam(q); msg != "" {
		s.flashRedirect(w, r, l.t("oauth.failed", msg), "/accounts")
		return
	}
	verifier, accountID, msgKey := s.consumeCallbackState(ctx, q)
	if msgKey != "" {
		s.flashRedirect(w, r, l.t(msgKey), "/accounts")
		return
	}
	cfg, err := s.Google.OAuthConfig(ctx, s.publicURL(r))
	if err != nil || cfg.ClientID == "" || cfg.ClientSecret == "" {
		s.flashRedirect(w, r, l.t("flash.oauth_missing"), "/settings")
		return
	}
	grant, err := s.completeGrant(ctx, cfg, accountID, q.Get("code"), verifier)
	if err != nil {
		s.flashRedirect(w, r, l.errorText(err), "/accounts")
		return
	}
	s.saveGrant(w, r, l, grant)
}

// oauthErrorParam returns Google's error (and description) from a denied
// consent, or "".
func oauthErrorParam(q url.Values) string {
	e := q.Get("error")
	if e == "" {
		return ""
	}
	if d := q.Get("error_description"); d != "" {
		return e + ": " + d
	}
	return e
}

// consumeCallbackState consumes the single-use state. msgKey names the
// message for a missing, expired or unknown state.
func (s *Server) consumeCallbackState(ctx context.Context, q url.Values) (verifier, accountID, msgKey string) {
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		return "", "", "oauth.missing_state"
	}
	verifier, accountID, err := s.Store.ConsumeOAuthState(ctx, state)
	switch {
	case errors.Is(err, store.ErrExpired):
		return "", "", "oauth.state_expired"
	case err != nil:
		return "", "", "oauth.state_invalid"
	}
	return verifier, accountID, ""
}

// oauthGrant is a completed consent: the tokens, the Google profile and the
// account it belongs to (nil for a new account).
type oauthGrant struct {
	cfg      google.OAuthConfig
	tok      *google.Token
	about    *google.About
	rootID   string
	name     string
	existing *store.Account
}

func (s *Server) completeGrant(ctx context.Context, cfg google.OAuthConfig, accountID, code, verifier string) (*oauthGrant, error) {
	g := &oauthGrant{cfg: cfg}
	if accountID != "" {
		existing, err := s.Store.GetAccount(ctx, accountID)
		if err != nil {
			return nil, err
		}
		useAccountClient(existing, &g.cfg)
		g.existing = existing
	}
	tok, err := s.Google.Exchange(ctx, g.cfg, code, verifier)
	if err != nil {
		return nil, err
	}
	g.tok = tok
	if err := s.loadGrantProfile(ctx, g); err != nil {
		return nil, err
	}
	if g.existing == nil {
		g.existing, err = s.accountByEmail(ctx, g.about.Email)
	}
	return g, err
}

// loadGrantProfile reads the Google profile and Drive root with the fresh
// access token, before the account row exists.
func (s *Server) loadGrantProfile(ctx context.Context, g *oauthGrant) error {
	temp := &store.Account{
		ID:           "oauth-pending-" + store.NewID(),
		ClientID:     g.cfg.ClientID,
		ClientSecret: g.cfg.ClientSecret,
		RefreshToken: g.tok.RefreshToken,
		AccessToken:  g.tok.AccessToken,
		TokenExpiry:  g.tok.Expiry,
	}
	about, err := s.Google.About(ctx, temp)
	if err != nil {
		return err
	}
	g.about = about
	// The root id is cached for speed; Drive resolves it again on demand.
	if g.rootID, err = s.Google.RootFolderID(ctx, temp); err != nil {
		s.Log.Warn("resolve Drive root during OAuth", "email", about.Email, "err", err)
	}
	local, _, _ := strings.Cut(about.Email, "@")
	g.name = cmp.Or(strings.TrimSpace(about.Name), local, "Google Drive")
	return nil
}

// accountByEmail finds an already connected account for the same Google
// user, so a repeated consent updates it instead of adding a duplicate.
func (s *Server) accountByEmail(ctx context.Context, email string) (*store.Account, error) {
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	for _, a := range accounts {
		if strings.EqualFold(a.Email, email) {
			return a, nil
		}
	}
	return nil, nil
}

func (s *Server) saveGrant(w http.ResponseWriter, r *http.Request, l *lang, g *oauthGrant) {
	if g.existing != nil {
		if err := s.updateGrantAccount(r.Context(), g); err != nil {
			s.flashRedirect(w, r, l.errorText(err), "/accounts")
			return
		}
		s.setFlash(w, r, "ok", l.t("flash.account_updated", g.about.Email))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if g.tok.RefreshToken == "" {
		s.flashRedirect(w, r, l.t("oauth.no_refresh"), "/accounts")
		return
	}
	acct := &store.Account{
		Name: g.name, Email: g.about.Email, Picture: g.about.Picture,
		ClientID: g.cfg.ClientID, ClientSecret: g.cfg.ClientSecret,
		RefreshToken: g.tok.RefreshToken, AccessToken: g.tok.AccessToken,
		TokenExpiry: g.tok.Expiry, RootID: g.rootID,
	}
	if err := s.Store.CreateAccount(r.Context(), acct); err != nil {
		s.flashRedirect(w, r, l.errorText(err), "/accounts")
		return
	}
	s.setFlash(w, r, "ok", l.t("flash.account_connected", g.about.Email))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// updateGrantAccount stores new tokens on an existing account; Google omits
// the refresh token on a repeated consent, so the old one is kept then.
func (s *Server) updateGrantAccount(ctx context.Context, g *oauthGrant) error {
	e := g.existing
	refresh := cmp.Or(g.tok.RefreshToken, e.RefreshToken)
	root := cmp.Or(g.rootID, e.RootID)
	if err := s.Store.UpdateAccountOAuth(ctx, e.ID, g.cfg.ClientID, g.cfg.ClientSecret, refresh,
		g.tok.AccessToken, g.tok.Expiry, root); err != nil {
		return err
	}
	return s.Store.UpdateAccountProfile(ctx, e.ID, g.name, g.about.Email, g.about.Picture, root)
}

func randomState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

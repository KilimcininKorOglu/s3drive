package webui

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"s3drive/internal/google"
	"s3drive/internal/store"
)

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
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		s.setFlash(w, "error", l.t("flash.oauth_missing"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	accountID := strings.TrimSpace(r.URL.Query().Get("account"))
	loginHint := ""
	if accountID != "" {
		acct, err := s.Store.GetAccount(ctx, accountID)
		if err != nil {
			s.setFlash(w, "error", l.errorText(err))
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
			return
		}
		// Accounts authorized with their own OAuth client keep using it.
		if acct.ClientID != "" && acct.ClientSecret != "" {
			cfg.ClientID, cfg.ClientSecret = acct.ClientID, acct.ClientSecret
		}
		loginHint = acct.Email
	}

	state, err := randomState()
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	verifier, challenge, err := google.NewVerifier()
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if err := s.Store.CreateOAuthState(ctx, state, verifier, accountID); err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, google.AuthCodeURL(cfg, state, challenge, loginHint), http.StatusSeeOther)
}

// oauthCallback validates the state, exchanges the code, stores the refresh
// token and refreshes the account profile.
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	ctx := r.Context()
	q := r.URL.Query()

	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		s.setFlash(w, "error", l.t("oauth.failed", msg))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		s.setFlash(w, "error", l.t("oauth.missing_state"))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	verifier, accountID, err := s.Store.ConsumeOAuthState(ctx, state)
	if err != nil {
		if errors.Is(err, store.ErrExpired) {
			s.setFlash(w, "error", l.t("oauth.state_expired"))
		} else {
			s.setFlash(w, "error", l.t("oauth.state_invalid"))
		}
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	cfg, err := s.Google.OAuthConfig(ctx, s.publicURL(r))
	if err != nil || cfg.ClientID == "" || cfg.ClientSecret == "" {
		s.setFlash(w, "error", l.t("flash.oauth_missing"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	var existing *store.Account
	if accountID != "" {
		existing, err = s.Store.GetAccount(ctx, accountID)
		if err != nil {
			s.setFlash(w, "error", l.errorText(err))
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
			return
		}
		if existing.ClientID != "" && existing.ClientSecret != "" {
			cfg.ClientID, cfg.ClientSecret = existing.ClientID, existing.ClientSecret
		}
	}

	tok, err := s.Google.Exchange(ctx, cfg, code, verifier)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	// About and RootFolderID work from the fresh access token, before the
	// account row exists.
	temp := &store.Account{
		ID:           "oauth-pending-" + store.NewID(),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RefreshToken: tok.RefreshToken,
		AccessToken:  tok.AccessToken,
		TokenExpiry:  tok.Expiry,
	}
	about, err := s.Google.About(ctx, temp)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	rootID, _ := s.Google.RootFolderID(ctx, temp)

	name := strings.TrimSpace(about.Name)
	if name == "" {
		name = strings.SplitN(about.Email, "@", 2)[0]
	}
	if name == "" {
		name = "Google Drive"
	}

	if existing == nil {
		accounts, _ := s.Store.ListAccounts(ctx)
		for _, a := range accounts {
			if strings.EqualFold(a.Email, about.Email) {
				existing = a
				break
			}
		}
	}

	if existing != nil {
		refresh := tok.RefreshToken
		if refresh == "" {
			refresh = existing.RefreshToken
		}
		root := rootID
		if root == "" {
			root = existing.RootID
		}
		if err := s.Store.UpdateAccountOAuth(ctx, existing.ID, cfg.ClientID, cfg.ClientSecret, refresh,
			tok.AccessToken, tok.Expiry, root); err != nil {
			s.setFlash(w, "error", l.errorText(err))
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
			return
		}
		if err := s.Store.UpdateAccountProfile(ctx, existing.ID, name, about.Email, about.Picture, root); err != nil {
			s.setFlash(w, "error", l.errorText(err))
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
			return
		}
		s.setFlash(w, "ok", l.t("flash.account_updated", about.Email))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	if tok.RefreshToken == "" {
		s.setFlash(w, "error", l.t("oauth.no_refresh"))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	acct := &store.Account{
		Name: name, Email: about.Email, Picture: about.Picture,
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		RefreshToken: tok.RefreshToken, AccessToken: tok.AccessToken,
		TokenExpiry: tok.Expiry, RootID: rootID,
	}
	if err := s.Store.CreateAccount(ctx, acct); err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	s.setFlash(w, "ok", l.t("flash.account_connected", about.Email))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

func randomState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

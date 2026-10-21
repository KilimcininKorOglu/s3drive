package google

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Settings keys shared with the web UI.
const (
	SettingClientID     = "oauth_client_id"
	SettingClientSecret = "oauth_client_secret"
)

// OAuthConfig is the installed OAuth application.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// OAuthConfig loads the client credentials from settings, falling back to
// S3DRIVE_GOOGLE_CLIENT_ID / S3DRIVE_GOOGLE_CLIENT_SECRET.
func (c *Client) OAuthConfig(ctx context.Context, publicURL string) (OAuthConfig, error) {
	cfg := OAuthConfig{
		ClientID:    strings.TrimSpace(os.Getenv("S3DRIVE_GOOGLE_CLIENT_ID")),
		RedirectURL: strings.TrimRight(publicURL, "/") + "/oauth/callback",
	}
	if cfg.ClientID == "" {
		v, err := c.Store.Setting(ctx, SettingClientID)
		if err != nil {
			return cfg, err
		}
		cfg.ClientID = v
	}
	secret := strings.TrimSpace(os.Getenv("S3DRIVE_GOOGLE_CLIENT_SECRET"))
	if secret == "" {
		enc, err := c.Store.Setting(ctx, SettingClientSecret)
		if err != nil {
			return cfg, err
		}
		if enc != "" {
			if secret, err = c.Store.Open(enc); err != nil {
				return cfg, err
			}
		}
	}
	cfg.ClientSecret = secret
	return cfg, nil
}

// ClientCredentials is a convenience wrapper used during token refresh.
func (c *Client) ClientCredentials(ctx context.Context) (string, string, error) {
	cfg, err := c.OAuthConfig(ctx, "")
	return cfg.ClientID, cfg.ClientSecret, err
}

// SaveOAuthConfig stores the OAuth client. The secret is encrypted at rest.
func (c *Client) SaveOAuthConfig(ctx context.Context, clientID, clientSecret string) error {
	enc, err := c.Store.Seal(clientSecret)
	if err != nil {
		return err
	}
	if err := c.Store.SetSetting(ctx, SettingClientID, strings.TrimSpace(clientID)); err != nil {
		return err
	}
	return c.Store.SetSetting(ctx, SettingClientSecret, enc)
}

// NewVerifier returns a PKCE code verifier and its S256 challenge.
func NewVerifier() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// AuthCodeURL builds the Google consent URL.
func AuthCodeURL(cfg OAuthConfig, state, challenge, loginHint string) string {
	v := url.Values{}
	v.Set("client_id", cfg.ClientID)
	v.Set("redirect_uri", cfg.RedirectURL)
	v.Set("response_type", "code")
	v.Set("scope", ScopeDrive)
	v.Set("access_type", "offline")
	v.Set("prompt", "consent")
	v.Set("include_granted_scopes", "true")
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	if loginHint != "" {
		v.Set("login_hint", loginHint)
	}
	return authURL + "?" + v.Encode()
}

// Exchange swaps an authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, cfg OAuthConfig, code, verifier string) (*Token, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("redirect_uri", cfg.RedirectURL)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		if oe.ErrorDescription != "" {
			return nil, fmt.Errorf("google oauth: %s", oe.ErrorDescription)
		}
		return nil, fmt.Errorf("google oauth failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, errors.New("google oauth returned no access token")
	}
	tok.Expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return &tok, nil
}

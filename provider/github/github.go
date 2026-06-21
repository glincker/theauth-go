// Package github implements theauth.Provider against GitHub's OAuth 2.0
// endpoints. Import this package only when you want GitHub sign-in; the
// root theauth package has no hard dependency on it.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
)

// defaultScopes are the minimum scopes needed to populate ProviderUser:
// read:user covers id/login/name/avatar, user:email lets us call /user/emails
// for primary verified email selection.
var defaultScopes = []string{"read:user", "user:email"}

// Endpoint URLs. Overridable via Config for tests (and theoretically for
// GitHub Enterprise installs, though that is not formally supported yet).
const (
	defaultAuthURL   = "https://github.com/login/oauth/authorize"
	defaultTokenURL  = "https://github.com/login/oauth/access_token"
	defaultUserURL   = "https://api.github.com/user"
	defaultEmailsURL = "https://api.github.com/user/emails"
)

// httpTimeout caps any single round trip to GitHub. Generous enough for slow
// network days, tight enough to keep handlers responsive under provider
// outages.
const httpTimeout = 10 * time.Second

// Config is the provider's wiring. ClientID + ClientSecret are required;
// everything else has a sensible default. Scopes default to read:user +
// user:email when nil.
type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string

	// Endpoint overrides for tests / GitHub Enterprise. Leave empty in
	// production to hit github.com directly.
	AuthorizeURL string
	TokenURL     string
	UserURL      string
	EmailsURL    string

	// HTTPClient lets callers inject a custom client (timeouts, transport
	// instrumentation, proxy). Defaults to a fresh client with httpTimeout.
	HTTPClient *http.Client
}

// provider is the concrete implementation of theauth.Provider for GitHub.
type provider struct {
	cfg          Config
	authorizeURL string
	tokenURL     string
	userURL      string
	emailsURL    string
	client       *http.Client
}

// New returns a GitHub theauth.Provider with the supplied Config.
// Required fields: ClientID, ClientSecret.
func New(cfg Config) theauth.Provider {
	p := &provider{
		cfg:          cfg,
		authorizeURL: orDefault(cfg.AuthorizeURL, defaultAuthURL),
		tokenURL:     orDefault(cfg.TokenURL, defaultTokenURL),
		userURL:      orDefault(cfg.UserURL, defaultUserURL),
		emailsURL:    orDefault(cfg.EmailsURL, defaultEmailsURL),
		client:       cfg.HTTPClient,
	}
	if p.client == nil {
		p.client = &http.Client{Timeout: httpTimeout}
	}
	if len(p.cfg.Scopes) == 0 {
		p.cfg.Scopes = defaultScopes
	}
	return p
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Name returns the stable registry key.
func (p *provider) Name() string { return "github" }

// AuthURL builds the authorize URL with PKCE params. Scopes are space-joined
// per RFC 6749 section 3.3.
func (p *provider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return p.authorizeURL + "?" + q.Encode()
}

// ExchangeCode posts the authorization code + PKCE verifier to GitHub's token
// endpoint and parses the JSON response. The Accept: application/json header
// tells GitHub to JSON-serialize the response (the default is form-encoded).
func (p *provider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64 KiB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("github token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("github token exchange: parse: %w", err)
	}
	if raw.Error != "" {
		return nil, fmt.Errorf("github token exchange: %s: %s", raw.Error, raw.ErrorDescription)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("github token exchange: missing access_token in response")
	}
	tok := &theauth.ProviderToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		Scope:        raw.Scope,
		TokenType:    raw.TokenType,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo fetches GET /user, then GET /user/emails, and merges them. The
// primary verified email is preferred; if none exists, the first verified
// email; failing that, the first email returned (with EmailVerified=false).
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("github: missing access token")
	}

	var u struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		Email     string `json:"email"`
	}
	if err := p.getJSON(ctx, p.userURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("github /user: %w", err)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	// /user/emails can fail on certain scopes; treat as soft-fail and fall
	// back to whatever email /user surfaced (often empty).
	if err := p.getJSON(ctx, p.emailsURL, token.AccessToken, &emails); err != nil {
		emails = nil
	}

	chosen, verified := pickEmail(emails, u.Email)

	name := u.Name
	if name == "" {
		name = u.Login
	}

	return &theauth.ProviderUser{
		ID:            strconv.FormatInt(u.ID, 10),
		Email:         chosen,
		EmailVerified: verified,
		Name:          name,
		AvatarURL:     u.AvatarURL,
	}, nil
}

// pickEmail picks the email to surface to the find-or-create flow. Per the
// v0.3 design doc: only "primary AND verified" counts as provider-verified;
// any other choice surfaces an address (so we have something to match on)
// with EmailVerified=false. Precedence for the address itself: primary
// verified > any verified > first available > /user fallback.
func pickEmail(emails []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}, fallback string) (string, bool) {
	var firstVerified, firstAny string
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true
		}
		if e.Verified && firstVerified == "" {
			firstVerified = e.Email
		}
		if firstAny == "" {
			firstAny = e.Email
		}
	}
	if firstVerified != "" {
		return firstVerified, false
	}
	if firstAny != "" {
		return firstAny, false
	}
	return fallback, false
}

func (p *provider) getJSON(ctx context.Context, url, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "theauth-go")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dst)
}

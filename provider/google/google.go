// Package google implements theauth.Provider against Google's OAuth 2.0
// and OIDC endpoints. Import this package only when you want Google
// sign-in; the root theauth package has no hard dependency on it.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
)

// defaultScopes are the minimum OIDC scopes needed to populate
// ProviderUser. openid is mandatory for any OIDC flow, email surfaces the
// address claim (plus the email_verified attestation), and profile gives
// us name + given_name + family_name + picture.
var defaultScopes = []string{"openid", "email", "profile"}

// Endpoint URLs. Overridable via Config for tests. In production, leave
// the fields empty and the defaults below are used.
const (
	defaultAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultTokenURL = "https://oauth2.googleapis.com/token"
	defaultUserURL  = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// httpTimeout caps any single round trip to Google. Generous enough for
// slow network days, tight enough to keep handlers responsive under
// provider outages.
const httpTimeout = 10 * time.Second

// Config is the provider's wiring. ClientID + ClientSecret are required;
// everything else has a sensible default.
type Config struct {
	ClientID     string
	ClientSecret string
	// Scopes optionally overrides the default OIDC scope set. nil or empty
	// uses [openid email profile].
	Scopes []string

	// Endpoint overrides for tests. Leave empty in production to hit
	// Google's published endpoints.
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string

	// HTTPClient lets callers inject a custom client (timeouts, transport
	// instrumentation, proxy). Defaults to a fresh client with httpTimeout.
	HTTPClient *http.Client
}

// provider is the concrete implementation of theauth.Provider for Google.
type provider struct {
	cfg          Config
	authorizeURL string
	tokenURL     string
	userInfoURL  string
	client       *http.Client
}

// New returns a Google theauth.Provider with the supplied Config.
// Required fields: ClientID, ClientSecret.
func New(cfg Config) theauth.Provider {
	p := &provider{
		cfg:          cfg,
		authorizeURL: orDefault(cfg.AuthorizeURL, defaultAuthURL),
		tokenURL:     orDefault(cfg.TokenURL, defaultTokenURL),
		userInfoURL:  orDefault(cfg.UserInfoURL, defaultUserURL),
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
func (p *provider) Name() string { return "google" }

// AuthURL builds the authorize URL with PKCE params. Scopes are space
// joined per RFC 6749 section 3.3. v0.4 does not request access_type or
// prompt so Google decides between consent and silent re-auth on its own
// heuristics; this also keeps the consent screen lighter for first time
// users.
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

// ExchangeCode posts the authorization code + PKCE verifier to Google's
// token endpoint and parses the JSON response.
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
		// Try to surface error + error_description if present so callers
		// can log a meaningful upstream reason.
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errBody)
		if errBody.Error != "" {
			return nil, fmt.Errorf("google token exchange: status=%d %s: %s", resp.StatusCode, errBody.Error, errBody.ErrorDescription)
		}
		return nil, fmt.Errorf("google token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("google token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("google token exchange: missing access_token in response")
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
	// id_token is intentionally not parsed in v0.4; signature verification
	// against JWKS lands in v0.5. We rely on the userinfo endpoint for
	// email_verified instead of the JWT claim.
	_ = raw.IDToken
	return tok, nil
}

// UserInfo calls Google's v3 userinfo endpoint and maps the OIDC claims
// into ProviderUser. Name fallback chain: name, then given+family, then
// the local part of email.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("google: missing access token")
	}

	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err := p.getJSON(ctx, p.userInfoURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("google /userinfo: %w", err)
	}

	name := u.Name
	if name == "" {
		if u.GivenName != "" || u.FamilyName != "" {
			name = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		}
	}
	if name == "" && u.Email != "" {
		if at := strings.IndexByte(u.Email, '@'); at > 0 {
			name = u.Email[:at]
		}
	}

	return &theauth.ProviderUser{
		ID:            u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          name,
		AvatarURL:     u.Picture,
	}, nil
}

func (p *provider) getJSON(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
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

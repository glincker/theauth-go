// Package x implements theauth.Provider against X's (formerly Twitter)
// OAuth 2.0 with PKCE endpoints. PKCE is mandatory for all X OAuth 2.0
// flows; the provider always sets code_challenge_method=S256 and requires
// a non-empty codeVerifier in ExchangeCode.
//
// References:
// https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
// https://developer.x.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
package x

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

// defaultScopes are the minimum scopes needed to populate ProviderUser.
// tweet.read is required; users.read surfaces the user object; offline.access
// gives a refresh token for long-lived sessions.
var defaultScopes = []string{"tweet.read", "users.read", "offline.access"}

const (
	defaultAuthURL  = "https://twitter.com/i/oauth2/authorize"
	defaultTokenURL = "https://api.twitter.com/2/oauth2/token"
	defaultUserURL  = "https://api.twitter.com/2/users/me"
)

// userFields requested from the X Users API v2.
const userFields = "id,name,username,profile_image_url"

const httpTimeout = 10 * time.Second

// Config is the provider wiring. ClientID + ClientSecret are required.
// Note: X OAuth 2.0 apps created after 2023 may be configured as
// "Confidential Client" (requires ClientSecret) or "Public Client"
// (PKCE-only, no secret). This implementation targets confidential clients;
// for public client apps leave ClientSecret empty and X will accept the
// request without it.
type Config struct {
	ClientID     string
	ClientSecret string // May be empty for public client apps.
	Scopes       []string

	// Endpoint overrides for tests. Leave empty in production.
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string

	HTTPClient *http.Client
}

type provider struct {
	cfg          Config
	authorizeURL string
	tokenURL     string
	userInfoURL  string
	client       *http.Client
}

// New returns an X theauth.Provider with the supplied Config.
// Required fields: ClientID. PKCE is always enabled (mandatory for X).
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
func (p *provider) Name() string { return "x" }

// AuthURL builds the authorize URL with PKCE params. PKCE (S256) is
// mandatory for X OAuth 2.0 flows.
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

// ExchangeCode posts the authorization code + PKCE verifier to X's token
// endpoint. For confidential clients, X requires HTTP Basic auth with
// ClientID and ClientSecret. For public clients, omit the Authorization
// header (leave ClientSecret empty).
func (p *provider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	if codeVerifier == "" {
		return nil, fmt.Errorf("x: PKCE code_verifier is mandatory for X OAuth 2.0")
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", p.cfg.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Confidential clients use Basic auth; public clients skip this.
	if p.cfg.ClientSecret != "" {
		req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errBody)
		if errBody.Error != "" {
			return nil, fmt.Errorf("x token exchange: status=%d %s: %s", resp.StatusCode, errBody.Error, errBody.ErrorDescription)
		}
		return nil, fmt.Errorf("x token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("x token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("x token exchange: missing access_token in response")
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

// UserInfo calls the X API v2 /2/users/me endpoint with the user.fields
// needed to populate ProviderUser. Note: X does not surface email via the
// Users v2 API unless the app has been granted elevated access and the user
// has verified their email. Email is left empty when not available.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("x: missing access token")
	}

	endpoint := p.userInfoURL + "?user.fields=" + url.QueryEscape(userFields)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("x /2/users/me: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("x /2/users/me: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("x /2/users/me: parse: %w", err)
	}

	d := payload.Data
	return &theauth.ProviderUser{
		ID:            d.ID,
		Email:         "", // X does not expose email via users/me without elevated app access.
		EmailVerified: false,
		Name:          d.Name,
		AvatarURL:     d.ProfileImageURL,
	}, nil
}

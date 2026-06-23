// Package slack implements theauth.Provider against Slack's OpenID Connect
// endpoints (Sign in with Slack). Import this package only when you want
// Slack sign-in; the root theauth package has no hard dependency on it.
//
// References:
// https://api.slack.com/authentication/sign-in-with-slack
// https://api.slack.com/methods/openid.connect.userInfo
package slack

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

// defaultScopes are the minimum OIDC scopes for Sign in with Slack.
var defaultScopes = []string{"openid", "email", "profile"}

const (
	defaultAuthURL  = "https://slack.com/openid/connect/authorize"
	defaultTokenURL = "https://slack.com/api/openid.connect.token"
	defaultUserURL  = "https://slack.com/api/openid.connect.userInfo"
)

const httpTimeout = 10 * time.Second

// Config is the provider wiring. ClientID + ClientSecret are required.
type Config struct {
	ClientID     string
	ClientSecret string
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

// New returns a Slack theauth.Provider with the supplied Config.
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
func (p *provider) Name() string { return "slack" }

// AuthURL builds the authorize URL with PKCE params.
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

// ExchangeCode posts the authorization code to Slack's OIDC token endpoint.
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("slack token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		OK          bool   `json:"ok"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("slack token exchange: parse: %w", err)
	}
	if !raw.OK || raw.Error != "" {
		return nil, fmt.Errorf("slack token exchange: %s", raw.Error)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("slack token exchange: missing access_token in response")
	}
	tok := &theauth.ProviderToken{
		AccessToken: raw.AccessToken,
		TokenType:   raw.TokenType,
		Scope:       raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo calls the Slack openid.connect.userInfo endpoint.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("slack: missing access token")
	}

	var u struct {
		OK            bool   `json:"ok"`
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Error         string `json:"error"`
	}
	if err := p.getJSON(ctx, p.userInfoURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("slack openid.connect.userInfo: %w", err)
	}
	if !u.OK || u.Error != "" {
		return nil, fmt.Errorf("slack openid.connect.userInfo: %s", u.Error)
	}

	return &theauth.ProviderUser{
		ID:            u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dst)
}

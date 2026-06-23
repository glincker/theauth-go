// Package bitbucket implements theauth.Provider against Bitbucket Cloud's
// OAuth 2.0 endpoints. Import this package only when you want Bitbucket
// sign-in; the root theauth package has no hard dependency on it.
//
// References:
// https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/
// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-users/#api-user-get
package bitbucket

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
// account covers id, display_name, and avatar; email surfaces the primary
// confirmed email.
var defaultScopes = []string{"account", "email"}

const (
	defaultAuthURL  = "https://bitbucket.org/site/oauth2/authorize"
	defaultTokenURL = "https://bitbucket.org/site/oauth2/access_token"
	defaultUserURL  = "https://api.bitbucket.org/2.0/user"
	defaultEmailURL = "https://api.bitbucket.org/2.0/user/emails"
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
	UserURL      string
	EmailURL     string

	HTTPClient *http.Client
}

type provider struct {
	cfg          Config
	authorizeURL string
	tokenURL     string
	userURL      string
	emailURL     string
	client       *http.Client
}

// New returns a Bitbucket theauth.Provider with the supplied Config.
// Required fields: ClientID, ClientSecret.
func New(cfg Config) theauth.Provider {
	p := &provider{
		cfg:          cfg,
		authorizeURL: orDefault(cfg.AuthorizeURL, defaultAuthURL),
		tokenURL:     orDefault(cfg.TokenURL, defaultTokenURL),
		userURL:      orDefault(cfg.UserURL, defaultUserURL),
		emailURL:     orDefault(cfg.EmailURL, defaultEmailURL),
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
func (p *provider) Name() string { return "bitbucket" }

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

// ExchangeCode posts the authorization code to Bitbucket's token endpoint.
// Bitbucket requires HTTP Basic auth for the client credentials.
func (p *provider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	form := url.Values{}
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
	// Bitbucket uses Basic auth for client credentials instead of body params.
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)

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
			return nil, fmt.Errorf("bitbucket token exchange: status=%d %s: %s", resp.StatusCode, errBody.Error, errBody.ErrorDescription)
		}
		return nil, fmt.Errorf("bitbucket token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scopes       string `json:"scopes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("bitbucket token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("bitbucket token exchange: missing access_token in response")
	}
	tok := &theauth.ProviderToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scopes,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo fetches /2.0/user and /2.0/user/emails, preferring the primary
// confirmed email.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("bitbucket: missing access token")
	}

	var u struct {
		AccountID   string `json:"account_id"`
		DisplayName string `json:"display_name"`
		Links       struct {
			Avatar struct {
				Href string `json:"href"`
			} `json:"avatar"`
		} `json:"links"`
	}
	if err := p.getJSON(ctx, p.userURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("bitbucket /2.0/user: %w", err)
	}

	// Fetch emails; soft-fail if the scope is not granted.
	email, verified := p.fetchPrimaryEmail(ctx, token.AccessToken)

	return &theauth.ProviderUser{
		ID:            u.AccountID,
		Email:         email,
		EmailVerified: verified,
		Name:          u.DisplayName,
		AvatarURL:     u.Links.Avatar.Href,
	}, nil
}

func (p *provider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool) {
	var payload struct {
		Values []struct {
			Email       string `json:"email"`
			IsPrimary   bool   `json:"is_primary"`
			IsConfirmed bool   `json:"is_confirmed"`
		} `json:"values"`
	}
	if err := p.getJSON(ctx, p.emailURL, accessToken, &payload); err != nil {
		return "", false
	}
	var first string
	for _, e := range payload.Values {
		if first == "" {
			first = e.Email
		}
		if e.IsPrimary && e.IsConfirmed {
			return e.Email, true
		}
	}
	return first, false
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

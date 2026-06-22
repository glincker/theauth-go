// Package facebook implements theauth.Provider against Meta's OAuth 2.0
// endpoints. Import this package only when you want Facebook sign-in; the
// root theauth package has no hard dependency on it.
//
// References:
// https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow
// https://developers.facebook.com/docs/graph-api/reference/user/
package facebook

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

// defaultScopes are the minimum permissions needed to populate ProviderUser.
// email surfaces the address; public_profile covers id, name, and picture.
var defaultScopes = []string{"email", "public_profile"}

const (
	defaultAuthURL  = "https://www.facebook.com/v20.0/dialog/oauth"
	defaultTokenURL = "https://graph.facebook.com/v20.0/oauth/access_token"
	defaultUserURL  = "https://graph.facebook.com/me"
)

// userInfoFields are the Graph API fields requested on /me.
const userInfoFields = "id,email,name,picture.type(large)"

const httpTimeout = 10 * time.Second

// Config is the provider wiring. ClientID + ClientSecret are required;
// everything else has a sensible default.
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

// New returns a Facebook theauth.Provider with the supplied Config.
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
func (p *provider) Name() string { return "facebook" }

// AuthURL builds the authorize URL with PKCE params.
func (p *provider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, ","))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return p.authorizeURL + "?" + q.Encode()
}

// ExchangeCode posts the authorization code to Facebook's token endpoint.
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
		var errBody struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    int    `json:"code"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal(body, &errBody); jsonErr == nil && errBody.Error.Message != "" {
			return nil, fmt.Errorf("facebook token exchange: status=%d %s (type=%s code=%d)",
				resp.StatusCode, errBody.Error.Message, errBody.Error.Type, errBody.Error.Code)
		}
		return nil, fmt.Errorf("facebook token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("facebook token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("facebook token exchange: missing access_token in response")
	}
	tok := &theauth.ProviderToken{
		AccessToken: raw.AccessToken,
		TokenType:   raw.TokenType,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo calls the Graph API /me endpoint with the required fields.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("facebook: missing access token")
	}

	endpoint := p.userInfoURL + "?fields=" + userInfoFields + "&access_token=" + url.QueryEscape(token.AccessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook /me: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("facebook /me: status=%d body=%s", resp.StatusCode, string(body))
	}

	var u struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("facebook /me: parse: %w", err)
	}

	// Facebook only returns email when the user has granted the email
	// permission AND has a confirmed email address on their account.
	// EmailVerified is not surfaced by the Graph API; callers should treat
	// Meta-verified status as implicit when email is present, but we
	// conservatively set it to false.
	return &theauth.ProviderUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: false,
		Name:          u.Name,
		AvatarURL:     u.Picture.Data.URL,
	}, nil
}

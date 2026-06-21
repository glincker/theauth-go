// Package discord implements theauth.Provider against Discord's OAuth
// 2.0 endpoints. Import this package only when you want Discord sign-in;
// the root theauth package has no hard dependency on it.
package discord

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
// identify covers id + username + global_name + avatar; email surfaces
// the email + verified pair on /users/@me.
var defaultScopes = []string{"identify", "email"}

const (
	defaultAuthURL  = "https://discord.com/api/oauth2/authorize"
	defaultTokenURL = "https://discord.com/api/oauth2/token"
	defaultUserURL  = "https://discord.com/api/users/@me"
)

// cdnAvatarURLFormat is the public CDN URL template for user avatars.
// id is the user's snowflake, hash is the avatar field returned by
// /users/@me. We render as PNG; Discord serves multiple formats but PNG
// is the most consumer friendly for downstream rendering.
const cdnAvatarURLFormat = "https://cdn.discordapp.com/avatars/%s/%s.png"

const httpTimeout = 10 * time.Second

// Config is the provider's wiring. ClientID + ClientSecret are required;
// everything else has a sensible default. Scopes default to
// [identify email] when nil.
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

// New returns a Discord theauth.Provider with the supplied Config.
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
func (p *provider) Name() string { return "discord" }

// AuthURL builds the authorize URL with PKCE params. Discord expects
// space joined scopes per RFC 6749 section 3.3. We omit prompt so Discord
// skips the consent screen for users who have already authorized the app.
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

// ExchangeCode posts the authorization code + PKCE verifier to Discord's
// token endpoint and parses the JSON response. Discord returns refresh
// tokens by default; v0.4 stores them encrypted via the existing
// oauth_accounts flow but does not auto-refresh (v0.5).
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
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errBody)
		if errBody.Error != "" {
			return nil, fmt.Errorf("discord token exchange: status=%d %s: %s", resp.StatusCode, errBody.Error, errBody.ErrorDescription)
		}
		return nil, fmt.Errorf("discord token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("discord token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("discord token exchange: missing access_token in response")
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

// UserInfo calls Discord's /users/@me endpoint and maps the response
// into ProviderUser. Name prefers global_name (the post-2023 display
// name) and falls back to username. EmailVerified mirrors Discord's
// verified field. AvatarURL is synthesized from the avatar hash when
// non-empty; default avatars are intentionally not synthesized so
// consumers can render their own placeholder.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("discord: missing access token")
	}

	var u struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Avatar     string `json:"avatar"`
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
	}
	if err := p.getJSON(ctx, p.userInfoURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("discord /users/@me: %w", err)
	}

	name := u.GlobalName
	if name == "" {
		name = u.Username
	}
	avatarURL := ""
	if u.Avatar != "" && u.ID != "" {
		avatarURL = fmt.Sprintf(cdnAvatarURLFormat, u.ID, u.Avatar)
	}

	return &theauth.ProviderUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.Verified,
		Name:          name,
		AvatarURL:     avatarURL,
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

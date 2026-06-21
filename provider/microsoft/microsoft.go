// Package microsoft implements theauth.Provider against the Microsoft
// identity platform v2.0 (Azure AD / Entra ID). Import this package only
// when you want Microsoft sign-in; the root theauth package has no hard
// dependency on it.
package microsoft

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
// ProviderUser plus get an id_token from the v2.0 endpoint. Microsoft's
// v2.0 endpoint uses scope-based consent, so additional Graph scopes can
// be passed through via Config.Scopes verbatim.
var defaultScopes = []string{"openid", "email", "profile"}

// defaultTenant is the multi-tenant authority that accepts any work,
// school, or personal Microsoft account. Single tenant apps should pass
// a tenant GUID or verified domain via Config.Tenant.
const defaultTenant = "common"

// tenantPlaceholder is the literal substring substituted with cfg.Tenant
// inside the authorize and token URL templates.
const tenantPlaceholder = "{tenant}"

const (
	defaultAuthURLTemplate  = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
	defaultTokenURLTemplate = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
	defaultUserURL          = "https://graph.microsoft.com/oidc/userinfo"
)

const httpTimeout = 10 * time.Second

// Config is the provider's wiring. ClientID + ClientSecret are required.
// Tenant selects which AAD authority to use (default "common").
type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string

	// Tenant selects which AAD authority to use. Valid values: "common"
	// (default, any work / school / personal Microsoft account),
	// "organizations" (work / school only), "consumers" (personal only),
	// or a tenant GUID / verified domain for single tenant apps.
	Tenant string

	// Endpoint overrides for tests. AuthorizeURL and TokenURL, if set,
	// bypass the Tenant substitution entirely (used verbatim).
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

// New returns a Microsoft theauth.Provider with the supplied Config.
// Required fields: ClientID, ClientSecret.
func New(cfg Config) theauth.Provider {
	tenant := cfg.Tenant
	if tenant == "" {
		tenant = defaultTenant
	}
	authorizeURL := cfg.AuthorizeURL
	if authorizeURL == "" {
		authorizeURL = strings.ReplaceAll(defaultAuthURLTemplate, tenantPlaceholder, tenant)
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = strings.ReplaceAll(defaultTokenURLTemplate, tenantPlaceholder, tenant)
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = defaultUserURL
	}
	p := &provider{
		cfg:          cfg,
		authorizeURL: authorizeURL,
		tokenURL:     tokenURL,
		userInfoURL:  userInfoURL,
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

// Name returns the stable registry key.
func (p *provider) Name() string { return "microsoft" }

// AuthURL builds the authorize URL with PKCE params. response_mode is
// left at the v2.0 default (query) since the callback handler is GET only.
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

// ExchangeCode posts the authorization code + PKCE verifier to
// Microsoft's tenant-scoped token endpoint and parses the JSON response.
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
			return nil, fmt.Errorf("microsoft token exchange: status=%d %s: %s", resp.StatusCode, errBody.Error, errBody.ErrorDescription)
		}
		return nil, fmt.Errorf("microsoft token exchange: status=%d body=%s", resp.StatusCode, string(body))
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
		return nil, fmt.Errorf("microsoft token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("microsoft token exchange: missing access_token in response")
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
	_ = raw.IDToken // not verified in v0.4; JWKS lands in v0.5
	return tok, nil
}

// UserInfo calls Microsoft's OIDC userinfo endpoint and maps the standard
// OIDC claims into ProviderUser. Email falls back to preferred_username
// when missing. Name falls back to preferred_username. ID is always sub,
// never oid (oid is the user object id and would leak across apps).
// EmailVerified is always false because the OIDC userinfo endpoint does
// not return an email_verified claim.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("microsoft: missing access token")
	}

	var u struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := p.getJSON(ctx, p.userInfoURL, token.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("microsoft /userinfo: %w", err)
	}

	email := u.Email
	if email == "" {
		email = u.PreferredUsername
	}
	name := u.Name
	if name == "" {
		name = u.PreferredUsername
	}

	return &theauth.ProviderUser{
		ID:            u.Sub,
		Email:         email,
		EmailVerified: false,
		Name:          name,
		AvatarURL:     "", // /me/photo requires a separate Graph scope and binary fetch; deferred to v0.5
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

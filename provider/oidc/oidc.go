package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/provider/internal/refresh"
)

const httpTimeout = 10 * time.Second

var defaultScopes = []string{"openid", "email", "profile"}

// Config wires a generic OIDC provider. Issuer, ClientID and ClientSecret
// are required.
type Config struct {
	// Name is the registry key and route segment. Defaults to "oidc".
	Name string
	// Issuer is the issuer URL; discovery reads Issuer + "/.well-known/openid-configuration".
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// AllowedAlgs limits accepted ID token algorithms. Defaults to RS256, ES256, PS256.
	AllowedAlgs []string
	// AllowInsecureHTTP permits http:// issuers; for tests and local IdPs only.
	AllowInsecureHTTP bool
	HTTPClient        *http.Client

	// DiscoveryURL overrides the discovery document location, for IdPs that
	// publish it somewhere other than Issuer + "/.well-known/openid-configuration"
	// (for example a tenant-scoped path). The issuer inside the document must
	// still equal Issuer.
	DiscoveryURL string
	// Endpoints overrides individual endpoints after discovery. Set
	// AuthorizationEndpoint, TokenEndpoint and JWKSURI together with
	// DisableDiscovery to run against an IdP that serves no discovery document.
	Endpoints Endpoints
	// DisableDiscovery skips the discovery request. Requires Endpoints.
	DisableDiscovery bool

	// AdditionalAudiences lists extra aud values accepted besides ClientID,
	// for example the client ids of a sibling mobile or SPA app that share
	// your IdP. A token passes when its aud holds ClientID or any listed
	// value. The azp rule is unchanged: a token with several audiences must
	// carry azp equal to ClientID. Every listed audience is trusted to
	// identify tokens meant for you, so list only values you control.
	AdditionalAudiences []string

	// AllowedTenants restricts a multi-tenant issuer (one containing
	// "{tenantid}", or an Entra common, organizations or consumers issuer)
	// to these tid values, compared case-insensitively. Empty accepts any
	// tenant whose token iss matches its own tid; with the common endpoint
	// that means any Entra tenant, so set it unless you want that. Ignored
	// for single-tenant issuers, whose iss is compared exactly.
	AllowedTenants []string

	// Claims overrides which ID token claims fill the user profile.
	Claims ClaimMapping
}

// Endpoints are manual overrides for discovered OIDC endpoints. Empty
// fields keep the discovered value.
type Endpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	JWKSURI               string
}

type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

type provider struct {
	cfg    Config
	meta   metadata
	client *http.Client
	keys   *keySet
	basic  bool
	// template is the {tenantid} issuer template, empty for a
	// single-tenant issuer.
	template string
}

// New discovers the issuer's endpoints and returns the provider. The
// returned value also implements theauth.NonceProvider.
func New(ctx context.Context, cfg Config) (theauth.Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("oidc: Issuer, ClientID and ClientSecret are required")
	}
	if cfg.Name == "" {
		cfg.Name = "oidc"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	}
	if len(cfg.AllowedAlgs) == 0 {
		cfg.AllowedAlgs = []string{"RS256", "ES256", "PS256"}
	}
	insecureOK := cfg.AllowInsecureHTTP && strings.HasPrefix(cfg.Issuer, "http://")
	if !strings.HasPrefix(cfg.Issuer, "https://") && !insecureOK {
		return nil, errors.New("oidc: Issuer must be https")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	p := &provider{cfg: cfg, client: client}
	if cfg.DisableDiscovery {
		e := cfg.Endpoints
		if e.AuthorizationEndpoint == "" || e.TokenEndpoint == "" || e.JWKSURI == "" {
			return nil, errors.New("oidc: DisableDiscovery needs Endpoints.AuthorizationEndpoint, TokenEndpoint and JWKSURI")
		}
		p.meta = metadata{Issuer: cfg.Issuer}
		if isTemplateIssuer(cfg.Issuer) {
			p.template = cfg.Issuer
		}
	} else if err := p.discover(ctx); err != nil {
		return nil, err
	}
	if err := p.applyOverrides(); err != nil {
		return nil, err
	}
	p.keys = &keySet{uri: p.meta.JWKSURI, client: client}
	return p, nil
}

func (p *provider) discover(ctx context.Context) error {
	u := strings.TrimSuffix(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	if isTemplateIssuer(p.cfg.Issuer) {
		// A template has no discovery document of its own; read the
		// shared multi-tenant one.
		u = strings.TrimSuffix(strings.ReplaceAll(p.cfg.Issuer, tenantPlaceholder, "common"), "/") + "/.well-known/openid-configuration"
	}
	if p.cfg.DiscoveryURL != "" {
		u = p.cfg.DiscoveryURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return p.fail(StageDiscovery, 0, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return p.fail(StageDiscovery, resp.StatusCode, errors.New("unexpected status"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, &p.meta); err != nil {
		return p.fail(StageDiscovery, 0, errors.New("document is not valid JSON"))
	}
	if !issuerAccepted(p.cfg.Issuer, p.meta.Issuer) {
		return p.fail(StageDiscovery, 0, fmt.Errorf("issuer %q does not match configured %q", p.meta.Issuer, p.cfg.Issuer))
	}
	if isTemplateIssuer(p.meta.Issuer) {
		p.template = p.meta.Issuer
	}
	if p.meta.AuthorizationEndpoint == "" || p.meta.TokenEndpoint == "" || p.meta.JWKSURI == "" {
		return errors.New("oidc: discovery document is missing required endpoints")
	}
	if len(p.meta.CodeChallengeMethods) > 0 && !contains(p.meta.CodeChallengeMethods, "S256") {
		return errors.New("oidc: issuer does not support PKCE S256")
	}
	p.basic = len(p.meta.AuthMethods) > 0 && !contains(p.meta.AuthMethods, "client_secret_post") && contains(p.meta.AuthMethods, "client_secret_basic")
	return nil
}

// applyOverrides lays manual endpoints over the discovered metadata. Every
// override must be https unless AllowInsecureHTTP is set.
func (p *provider) applyOverrides() error {
	e := p.cfg.Endpoints
	for name, pair := range map[string]struct {
		dst *string
		v   string
	}{
		"AuthorizationEndpoint": {&p.meta.AuthorizationEndpoint, e.AuthorizationEndpoint},
		"TokenEndpoint":         {&p.meta.TokenEndpoint, e.TokenEndpoint},
		"UserinfoEndpoint":      {&p.meta.UserinfoEndpoint, e.UserinfoEndpoint},
		"JWKSURI":               {&p.meta.JWKSURI, e.JWKSURI},
	} {
		if pair.v == "" {
			continue
		}
		if !strings.HasPrefix(pair.v, "https://") && (!p.cfg.AllowInsecureHTTP || !strings.HasPrefix(pair.v, "http://")) {
			return fmt.Errorf("oidc: Endpoints.%s must be https", name)
		}
		*pair.dst = pair.v
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Name returns the registry key.
func (p *provider) Name() string { return p.cfg.Name }

// AuthURL builds an authorize URL without a nonce; the library always
// calls AuthURLWithNonce for this provider.
func (p *provider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	return p.AuthURLWithNonce(state, codeChallenge, "", redirectURI, scopes)
}

// AuthURLWithNonce builds the authorize URL with PKCE and the OIDC nonce.
func (p *provider) AuthURLWithNonce(state, codeChallenge, nonce, redirectURI string, scopes []string) string {
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
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	sep := "?"
	if strings.Contains(p.meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.meta.AuthorizationEndpoint + sep + q.Encode()
}

// ExchangeCode always fails: an OIDC login without a nonce is refused.
func (p *provider) ExchangeCode(context.Context, string, string, string) (*theauth.ProviderToken, error) {
	return nil, errors.New("oidc: nonce is required, use ExchangeCodeWithNonce")
}

// ExchangeCodeWithNonce trades the code for tokens and verifies the ID token
// including its nonce.
func (p *provider) ExchangeCodeWithNonce(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (*theauth.ProviderToken, error) {
	if nonce == "" {
		return nil, errors.New("oidc: empty nonce")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	if !p.basic {
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.basic {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, p.fail(StageExchange, 0, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, p.fail(StageExchange, resp.StatusCode, errors.New("token endpoint rejected the request"))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, p.fail(StageExchange, 0, errors.New("token response is not valid JSON"))
	}
	if tr.IDToken == "" {
		return nil, p.fail(StageExchange, 0, errors.New("token response has no id_token"))
	}
	claims, err := p.verify(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, p.fail(StageVerify, 0, errors.New("id_token nonce mismatch"))
	}
	tok := &theauth.ProviderToken{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		Scope:        tr.Scope,
		TokenType:    tr.TokenType,
		IDToken:      tr.IDToken,
	}
	if tr.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo derives the profile from the verified ID token, falling back to
// the userinfo endpoint for a missing email.
func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.IDToken == "" {
		return nil, errors.New("oidc: missing id_token")
	}
	claims, err := p.verify(ctx, token.IDToken)
	if err != nil {
		return nil, err
	}
	cm := p.cfg.Claims
	subClaim := cm.or("sub", cm.Subject)
	emailClaim := cm.or("email", cm.Email)
	sub, _ := claims[subClaim].(string)
	if sub == "" {
		return nil, p.fail(StageVerify, 0, fmt.Errorf("id_token has no %s claim", subClaim))
	}
	if _, ok := claims[emailClaim]; !ok && p.meta.UserinfoEndpoint != "" && token.AccessToken != "" {
		if extra, err := p.fetchUserinfo(ctx, token.AccessToken, claimString(claims, "sub")); err == nil {
			for k, v := range extra {
				if _, set := claims[k]; !set {
					claims[k] = v
				}
			}
		}
	}
	u := &theauth.ProviderUser{ID: sub}
	u.Email, _ = claims[emailClaim].(string)
	u.EmailVerified = truthy(claims[cm.or("email_verified", cm.EmailVerified)])
	u.Name, _ = claims[cm.or("name", cm.Name)].(string)
	u.AvatarURL, _ = claims[cm.or("picture", cm.Picture)].(string)
	return u, nil
}

func claimString(claims map[string]any, k string) string {
	s, _ := claims[k].(string)
	return s
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x == 1
	}
	return false
}

func (p *provider) fetchUserinfo(ctx context.Context, accessToken, sub string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.meta.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, p.fail(StageUserinfo, resp.StatusCode, errors.New("userinfo endpoint rejected the request"))
	}
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, err
	}
	if s, _ := out["sub"].(string); s != sub {
		return nil, p.fail(StageUserinfo, 0, errors.New("userinfo sub mismatch"))
	}
	return out, nil
}

// RefreshToken implements theauth.RefreshProvider with the standard
// refresh_token grant (RFC 6749 section 6).
func (p *provider) RefreshToken(ctx context.Context, refreshToken string) (*theauth.ProviderToken, error) {
	tok, err := refresh.Do(ctx, refresh.Request{
		Provider:     "oidc",
		TokenURL:     p.meta.TokenEndpoint,
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RefreshToken: refreshToken,
		BasicAuth:    p.basic,
		Client:       p.client,
	})
	if err != nil {
		return nil, p.fail(StageRefresh, 0, err)
	}
	if tok.IDToken != "" {
		// A refreshed ID token is optional; when present it must verify.
		if _, verr := p.verify(ctx, tok.IDToken); verr != nil {
			return nil, verr
		}
	}
	return tok, nil
}

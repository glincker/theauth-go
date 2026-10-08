// Package generic builds theauth.Provider values from a declarative Spec.
// Most "plain" OAuth 2.0 identity providers differ only in three URLs, a
// scope list and where the profile fields sit in the userinfo JSON, so one
// implementation driven by a table covers many of them. See catalog.go for
// the built-in table; callers can pass their own Spec for any other
// provider that follows the same shape.
//
// Providers that need a second request for the email, a non-JSON token
// response or a signed ID token do not fit this model and keep their own
// package (github, apple, oidc).
package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

const httpTimeout = 10 * time.Second

// Fields maps normalized profile fields to dotted JSON paths in the userinfo
// response. Each field lists alternatives; the first non-empty value wins.
// A path segment that is a number indexes into an array ("images.0.url").
type Fields struct {
	ID            []string
	Email         []string
	EmailVerified []string
	Name          []string
	AvatarURL     []string
}

// Spec describes one provider.
type Spec struct {
	// Name is the registry key. Lower case, URL safe.
	Name     string
	AuthURL  string
	TokenURL string
	UserURL  string
	// Scopes are used when neither Config nor the caller supplies any.
	Scopes []string
	// AuthParams are extra query parameters on the authorize URL.
	AuthParams map[string]string
	// TokenBasicAuth sends client credentials in an Authorization: Basic
	// header instead of the form body.
	TokenBasicAuth bool
	// ScopeSeparator joins scopes in the authorize URL. Default is a space.
	ScopeSeparator string
	// UserMethod is GET (default) or POST for the userinfo request.
	UserMethod string
	// UserQuery is appended to UserURL verbatim (already encoded).
	UserQuery string
	Fields    Fields
}

// Config carries per-deployment settings.
type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	// Name, AuthURL, TokenURL and UserURL override the Spec, for example to
	// point the codeberg spec at a self-hosted Gitea.
	Name     string
	AuthURL  string
	TokenURL string
	UserURL  string
	// HTTPClient defaults to a client with a 10 second timeout.
	HTTPClient *http.Client
}

type provider struct {
	spec   Spec
	cfg    Config
	client *http.Client
}

// New validates the spec and returns a provider.
func New(spec Spec, cfg Config) (theauth.Provider, error) {
	if cfg.Name != "" {
		spec.Name = cfg.Name
	}
	if cfg.AuthURL != "" {
		spec.AuthURL = cfg.AuthURL
	}
	if cfg.TokenURL != "" {
		spec.TokenURL = cfg.TokenURL
	}
	if cfg.UserURL != "" {
		spec.UserURL = cfg.UserURL
	}
	switch {
	case spec.Name == "":
		return nil, errors.New("generic: Name is required")
	case cfg.ClientID == "" || cfg.ClientSecret == "":
		return nil, fmt.Errorf("generic: %s: ClientID and ClientSecret are required", spec.Name)
	case spec.AuthURL == "" || spec.TokenURL == "" || spec.UserURL == "":
		return nil, fmt.Errorf("generic: %s: AuthURL, TokenURL and UserURL are required", spec.Name)
	case len(spec.Fields.ID) == 0:
		return nil, fmt.Errorf("generic: %s: Fields.ID is required", spec.Name)
	}
	if spec.UserMethod == "" {
		spec.UserMethod = http.MethodGet
	}
	if spec.ScopeSeparator == "" {
		spec.ScopeSeparator = " "
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	return &provider{spec: spec, cfg: cfg, client: client}, nil
}

func (p *provider) Name() string { return p.spec.Name }

func (p *provider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	if len(scopes) == 0 {
		scopes = p.spec.Scopes
	}
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, p.spec.ScopeSeparator))
	}
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	for k, v := range p.spec.AuthParams {
		q.Set(k, v)
	}
	sep := "?"
	if strings.Contains(p.spec.AuthURL, "?") {
		sep = "&"
	}
	return p.spec.AuthURL + sep + q.Encode()
}

func (p *provider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	if !p.spec.TokenBasicAuth {
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.spec.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.spec.TokenBasicAuth {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	body, status, err := p.do(req, 1<<16)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("%s token exchange: status %d", p.spec.Name, status)
	}
	var raw struct {
		AccessToken      string      `json:"access_token"`
		RefreshToken     string      `json:"refresh_token"`
		ExpiresIn        json.Number `json:"expires_in"`
		Scope            string      `json:"scope"`
		TokenType        string      `json:"token_type"`
		Error            string      `json:"error"`
		ErrorDescription string      `json:"error_description"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%s token exchange: parse: %w", p.spec.Name, err)
	}
	if raw.Error != "" {
		return nil, fmt.Errorf("%s token exchange: %s: %s", p.spec.Name, raw.Error, raw.ErrorDescription)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("%s token exchange: missing access_token", p.spec.Name)
	}
	tok := &theauth.ProviderToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		Scope:        raw.Scope,
		TokenType:    raw.TokenType,
	}
	if secs, err := raw.ExpiresIn.Int64(); err == nil && secs > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}

func (p *provider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("%s: missing access token", p.spec.Name)
	}
	target := p.spec.UserURL
	if p.spec.UserQuery != "" {
		target += "?" + p.spec.UserQuery
	}
	var reqBody io.Reader
	if p.spec.UserMethod == http.MethodPost {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, p.spec.UserMethod, target, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "theauth-go")
	body, status, err := p.do(req, 1<<20)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("%s userinfo: status %d", p.spec.Name, status)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s userinfo: parse: %w", p.spec.Name, err)
	}
	f := p.spec.Fields
	u := &theauth.ProviderUser{
		ID:        first(doc, f.ID),
		Email:     first(doc, f.Email),
		Name:      first(doc, f.Name),
		AvatarURL: first(doc, f.AvatarURL),
	}
	if u.ID == "" {
		return nil, fmt.Errorf("%s userinfo: no user id in response", p.spec.Name)
	}
	if u.Email != "" {
		u.EmailVerified = truthy(first(doc, f.EmailVerified))
	}
	return u, nil
}

func (p *provider) do(req *http.Request, limit int64) ([]byte, int, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b, resp.StatusCode, err
}

// first returns the first non-empty string found at any of paths.
func first(doc any, paths []string) string {
	for _, path := range paths {
		if s := lookup(doc, path); s != "" {
			return s
		}
	}
	return ""
}

func lookup(doc any, path string) string {
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(v) {
				return ""
			}
			cur = v[i]
		default:
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func truthy(s string) bool { return s == "true" || s == "1" }

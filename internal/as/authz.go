package as

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
)

// authz.go: GET /oauth/authorize state machine.
//
// Phase 1 + 2 ships a minimal consent path: when the user is already
// authenticated and the requested scope is a subset of the resource's
// catalog, the authorize endpoint issues an authorization code
// immediately and redirects. Consent screen rendering belongs to the
// consuming application; the AS surface stays headless. A consent screen
// overlay can be wired in a later phase by short-circuiting StartAuthorize.

// AuthorizeRequest is the parsed GET /oauth/authorize query string. PKCE
// fields are required; OAuth 2.1 forbids the legacy implicit and password
// flows so response_type MUST be "code" and code_challenge_method MUST be
// "S256".
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	Nonce               string
}

// AuthorizeResult is the outcome of a successful authorize call: the
// redirect URL the handler should 302 the user agent to.
type AuthorizeResult struct {
	RedirectURL string
}

// StartAuthorize validates the request and, when the supplied user is
// non-nil, immediately mints an authorization code bound to the request
// and returns a redirect URL with code + state. When user is nil the
// caller should redirect to LoginURL so the user can sign in.
func (s *Service) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *models.User) (result AuthorizeResult, err error) {
	if s == nil {
		return AuthorizeResult{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthAuthorize)
	defer func() {
		status := obs.StatusSuccess
		if err != nil && !errors.Is(err, errAuthorizeLoginRequired) {
			status = obs.StatusError
			span.RecordError(err)
			span.SetAttributes(obs.StringAttr(obs.AttrErrorCode, errorCode(err)))
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}()
	if req.ResponseType != models.ResponseTypeCode {
		return AuthorizeResult{}, models.ErrOAuthUnsupportedResponseType
	}
	if req.ClientID == "" {
		return AuthorizeResult{}, models.ErrOAuthInvalidRequest
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return AuthorizeResult{}, models.ErrOAuthInvalidRequest
	}
	if req.Resource == "" {
		return AuthorizeResult{}, models.ErrOAuthInvalidResource
	}
	resource, ok := s.ResourceByIdentifier(req.Resource)
	if !ok {
		return AuthorizeResult{}, models.ErrOAuthInvalidResource
	}
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err != nil {
		return AuthorizeResult{}, models.ErrOAuthInvalidClient
	}
	if !redirectURIRegistered(client.RedirectURIs, req.RedirectURI) {
		return AuthorizeResult{}, models.ErrOAuthInvalidRequest
	}
	scope, err := validateScopeAgainstResource(req.Scope, resource)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if user == nil {
		// Unauthenticated; let the caller redirect to LoginURL with a
		// `next` query so the user returns here after sign in. This
		// struct value signals login-required by returning an empty
		// RedirectURL.
		return AuthorizeResult{}, errAuthorizeLoginRequired
	}
	codeStr, err := crypto.NewToken()
	if err != nil {
		return AuthorizeResult{}, err
	}
	now := time.Now()
	if err := s.Storage.InsertAuthorizationCode(ctx, models.AuthorizationCode{
		Code:                codeStr,
		ClientID:            client.ClientID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               scope,
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		ExpiresAt:           now.Add(s.Cfg.AuthorizationCodeTTL),
		CreatedAt:           now,
	}); err != nil {
		return AuthorizeResult{}, err
	}
	redirectURL := buildAuthzRedirect(req.RedirectURI, codeStr, req.State)
	return AuthorizeResult{RedirectURL: redirectURL}, nil
}

// redirectURIRegistered returns true when the supplied URI exactly
// matches one of the registered URIs. OAuth 2.1 mandates exact match (no
// path substring matching).
func redirectURIRegistered(registered []string, uri string) bool {
	if uri == "" {
		return false
	}
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	return false
}

// buildAuthzRedirect appends ?code=...&state=... to the supplied redirect
// URI, preserving any pre-existing query parameters.
func buildAuthzRedirect(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// fallback: plain concat (the registered URI was already
		// validated as a parseable URL at client registration).
		return redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

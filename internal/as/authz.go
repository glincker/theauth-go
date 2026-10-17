package as

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
)

// authz.go implements the GET /oauth/authorize state machine. When the user is already
// authenticated and the scope fits the resource catalog, it issues a code immediately. Consent
// screens belong to the host (see consent.go).

// AuthorizeRequest is the parsed GET /oauth/authorize query. PKCE is required and response_type
// must be "code" (OAuth 2.1).
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

	// MaxAge is the OIDC max_age in seconds, nil when absent. An older authentication, or 0, requires
	// re-authentication.
	MaxAge *int64
	// ACRValues is the acr_values parameter. A session satisfies it when its acr equals one of them.
	ACRValues []string
	// Prompt is the OIDC prompt parameter. Only "none" is interpreted: it answers login_required
	// instead of redirecting.
	Prompt string

	// AuthorizationDetails is the raw RFC 9396 JSON array, empty when absent.
	AuthorizationDetails string

	// RequestURI identifies a pushed authorization request (RFC 9126). The handler resolves it before
	// StartAuthorize.
	RequestURI string

	// RequestObject is the raw JAR JWT (RFC 9101). The handler resolves it before StartAuthorize.
	RequestObject string
}

// AuthorizeResult is the redirect URL the handler sends the user agent to.
type AuthorizeResult struct {
	RedirectURL string
}

// StartAuthorize validates the request. With a user it mints a code and returns the redirect URL.
// With a nil user the caller redirects to LoginURL.
func (s *Service) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *models.User) (AuthorizeResult, error) {
	return s.startAuthorize(ctx, req, user, nil)
}

// startAuthorize is StartAuthorize plus the consent resume path, which applies a verified ticket
// and the host's decision.
func (s *Service) startAuthorize(ctx context.Context, req AuthorizeRequest, user *models.User, resume *consentResume) (result AuthorizeResult, err error) {
	if s == nil {
		return AuthorizeResult{}, errors.New("theauth: authorization server not configured")
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthAuthorize)
	defer func() {
		status := obs.StatusSuccess
		if err != nil && !errors.Is(err, errAuthorizeLoginRequired) && !errors.Is(err, errAuthorizeReauthRequired) {
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
	// RequireState rejects requests without a non-empty state parameter (security re-audit L5).
	// Without it the CSRF protection state provides is lost.
	if s.Cfg.RequireState && req.State == "" {
		return AuthorizeResult{}, models.ErrOAuthInvalidRequest
	}
	resource, audience, err := s.resolveResource(req.Resource)
	if err != nil {
		return AuthorizeResult{}, err
	}
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err != nil {
		return AuthorizeResult{}, models.ErrOAuthInvalidClient
	}
	if !s.redirectURIRegistered(client.RedirectURIs, req.RedirectURI) {
		return AuthorizeResult{}, models.ErrOAuthInvalidRequest
	}
	scope, err := s.narrowScopes(req.Scope, resource, client)
	if err != nil {
		return AuthorizeResult{}, err
	}
	_, details, err := s.parseAuthorizationDetails(client, req.AuthorizationDetails)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if user == nil {
		// An unauthenticated caller gets an empty RedirectURL, which signals that the caller should send
		// the user to login.
		return AuthorizeResult{}, errAuthorizeLoginRequired
	}
	now := time.Now()
	ac, haveAC := AuthContextFrom(ctx)
	if s.reauthNeeded(req, ac, haveAC, now) {
		return AuthorizeResult{}, errAuthorizeReauthRequired
	}
	var grantExpiry time.Time
	if s.Cfg.ConsentHandler != nil {
		out, err := s.consentStep(ctx, req, client, user, scope, resume)
		if err != nil {
			return AuthorizeResult{}, err
		}
		if out.redirect != "" {
			return AuthorizeResult{RedirectURL: out.redirect}, nil
		}
		scope, grantExpiry = out.scope, out.expiry
	}
	codeStr, err := crypto.NewToken()
	if err != nil {
		return AuthorizeResult{}, err
	}
	// The grant expiry rides inside the code and the refresh token. The stored key hashes the whole
	// string, so it cannot be changed.
	codeStr = withGrantExpiry(codeStr, grantExpiry)
	if err := s.Storage.InsertAuthorizationCode(ctx, models.AuthorizationCode{
		Code:                 codeStorageKey(codeStr),
		ClientID:             client.ClientID,
		UserID:               user.ID,
		RedirectURI:          req.RedirectURI,
		Scope:                scope,
		Resource:             audience,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Nonce:                req.Nonce,
		AuthorizationDetails: details,
		AuthTime:             ac.AuthTime.UTC(),
		ACR:                  s.acrFor(ac),
		AMR:                  ac.AMR,
		ExpiresAt:            now.Add(s.Cfg.AuthorizationCodeTTL),
		CreatedAt:            now,
	}); err != nil {
		return AuthorizeResult{}, err
	}
	if s.OIDCEnabled() && hasScope(scope, ScopeOpenID) {
		s.linkCodeSession(ctx, codeStorageKey(codeStr), ac.SessionID)
	}
	redirectURL := buildAuthzRedirect(req.RedirectURI, codeStr, req.State, s.Cfg.Issuer)
	return AuthorizeResult{RedirectURL: redirectURL}, nil
}

// RedirectURIRegisteredFor reports whether uri is registered for clientID, exactly or port-agnostic
// for loopback URIs when ClientCompat.LoopbackAnyPort is on. Never redirect to a URI this rejects.
func (s *Service) RedirectURIRegisteredFor(ctx context.Context, clientID, uri string) bool {
	client, err := s.ResolveClient(ctx, clientID)
	if err != nil || client == nil {
		return false
	}
	return s.redirectURIRegistered(client.RedirectURIs, uri)
}

// redirectURIRegistered reports an exact match against the registered URIs. OAuth 2.1 mandates
// exact matching.
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

// buildAuthzRedirect appends code and state to a redirect URI, keeping its existing query parameters.
func buildAuthzRedirect(redirectURI, code, state, issuer string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	if issuer != "" {
		// RFC 9207 mix-up defence: the iss parameter. It is advertised in the AS metadata.
		q.Set("iss", issuer)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

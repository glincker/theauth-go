package theauth

import (
	"context"
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_authz.go: thin forwarders for GET /oauth/authorize. PR B
// architecture reorg (2026-06-20) moved the implementation into
// internal/as; the exported request / result types are re-exported as
// aliases so the v2.0 public surface is unchanged.

// AuthorizeRequest is the parsed GET /oauth/authorize query string.
// PKCE fields are required; OAuth 2.1 forbids the legacy implicit and
// password flows so response_type MUST be "code" and
// code_challenge_method MUST be "S256".
type AuthorizeRequest = internalas.AuthorizeRequest

// AuthorizeResult is the outcome of a successful authorize call: the
// redirect URL the handler should 302 the user agent to.
type AuthorizeResult = internalas.AuthorizeResult

// StartAuthorize validates the request and, when the supplied user is
// non-nil, immediately mints an authorization code bound to the request
// and returns a redirect URL with code + state. When user is nil the
// caller should redirect to LoginURL so the user can sign in.
func (a *TheAuth) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *User) (AuthorizeResult, error) {
	if a.as == nil {
		return AuthorizeResult{}, errors.New("theauth: authorization server not configured")
	}
	return a.as.StartAuthorize(ctx, req, user)
}

// IsLoginRequired reports whether the supplied error signals the
// authorize path needs an authenticated user. Forwards to the extracted
// internal/as.IsLoginRequired; both packages share the same sentinel
// pointer so existing errors.Is callers keep working.
func IsLoginRequired(err error) bool {
	return internalas.IsLoginRequired(err)
}

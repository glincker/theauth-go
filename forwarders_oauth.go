package theauth

import (
	"context"
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// ErrAuthorizationServerNotConfigured is returned by authorization-server
// methods when Config.AuthorizationServer was not set at New time.
// Callers can use errors.Is(err, theauth.ErrAuthorizationServerNotConfigured)
// to distinguish this condition from other errors.
var ErrAuthorizationServerNotConfigured = errors.New("theauth: authorization server not configured")

// forwarders_oauth.go consolidates the v2.0 OAuth 2.1 authorization
// server forwarders (DCR, introspect, revoke, token grants, metadata,
// authorize) into a single file. PR G (2026-06-21) merged the previous
// service_dcr.go, service_introspect.go, service_revoke.go,
// service_token.go, service_token_v34.go, service_metadata.go,
// service_metadata_resource.go, and service_authz.go files here. Every
// method is a thin thunk over internalas.Service; the substantive
// implementations live in internal/as. No behaviour change; signatures
// are byte-stable with the v2.0 release.

// ---------- DCR (RFC 7591) ----------

// ClientRegistrationRequest is the parsed JSON body of POST
// /oauth/register. Field names match RFC 7591 client metadata exactly so
// the wire form maps 1:1 onto the struct.
type ClientRegistrationRequest = internalas.ClientRegistrationRequest

// RegisterClient validates the request, mints a client_id (and a secret
// for confidential clients), persists the OAuthClient row, and returns
// the RFC 7591 response body. The plaintext secret is in the return
// value; callers must surface it to the caller exactly once and never
// log it. Forwards to as.RegisterClient.
func (a *TheAuth) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (RegisteredClient, error) {
	if a.as == nil {
		return RegisteredClient{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.RegisterClient(ctx, req, anonymous)
}

// ---------- Introspection (RFC 7662) ----------

// IntrospectionResponse mirrors the JSON shape mandated by RFC 7662
// section 2.2 plus the v2.0 act chain and delegation_grant_id
// forward-compatibility fields.
type IntrospectionResponse = internalas.IntrospectionResponse

// IntrospectToken validates the supplied token and returns the
// structured introspection response. Token type detection: JWTs are
// recognised by the three dot-separated base64 segments; everything else
// is treated as a refresh token (looked up by hash).
//
// Audience binding: when expectedAud is non-empty (resource server
// passes its own identifier), tokens with a mismatching aud return
// active=false. Forwards to as.IntrospectToken.
func (a *TheAuth) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (IntrospectionResponse, []byte, error) {
	if a.as == nil {
		return IntrospectionResponse{}, nil, ErrAuthorizationServerNotConfigured
	}
	return a.as.IntrospectToken(ctx, token, clientID, clientSecret, expectedAud)
}

// ---------- Revocation (RFC 7009) ----------

// RevokeToken invalidates a refresh token. Authorization codes and
// access tokens are out of scope for this entry: codes are single-use
// anyway, and access tokens are stateless JWTs whose lifetime is
// bounded by exp. Forwards to as.RevokeToken.
func (a *TheAuth) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if a.as == nil {
		return ErrAuthorizationServerNotConfigured
	}
	return a.as.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
}

// ---------- Token grants ----------

// TokenRequest is the parsed form-encoded body of a POST /oauth/token
// call, plus the authenticated client extracted from the request line /
// headers.
type TokenRequest = internalas.TokenRequest

// TokenResponse is the JSON body emitted by /oauth/token on success.
type TokenResponse = internalas.TokenResponse

// TokenExchangeRequest is the parsed form-encoded body of a
// token-exchange call. Field names map 1:1 onto the RFC 8693 wire form.
type TokenExchangeRequest = internalas.TokenExchangeRequest

// ExchangeAuthorizationCode redeems a one-time authorization code for
// an access token + refresh token pair. Enforces PKCE S256,
// redirect_uri equality, audience binding (RFC 8707), and client
// authentication. Forwards to as.ExchangeAuthorizationCode.
func (a *TheAuth) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ExchangeAuthorizationCode(ctx, req)
}

// RefreshAccessToken rotates a refresh token, returning a new access
// token + refresh token pair. The old refresh token is revoked;
// presenting it again triggers family-wide revocation per RFC 9700
// section 4.14. Forwards to as.RefreshAccessToken.
func (a *TheAuth) RefreshAccessToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.RefreshAccessToken(ctx, req)
}

// ClientCredentialsToken mints a self-token for the authenticated agent
// client. The token's sub is "agent:<id>"; aud is bound to the resource
// parameter (RFC 8707); scope is intersected with both the agent's
// registered scope set and the resource catalog. Suspended / revoked
// agents fail with ErrAgentInactive (mapped to access_denied at the
// wire).
//
// Audit emission: agent.token_minted on success. Forwards to
// as.ClientCredentialsToken.
func (a *TheAuth) ClientCredentialsToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ClientCredentialsToken(ctx, req)
}

// ExchangeToken implements RFC 8693 token exchange. Forwards to
// as.ExchangeToken.
func (a *TheAuth) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (TokenResponse, error) {
	return a.as.ExchangeToken(ctx, req)
}

// Note: the previous unexported helper authenticateClient was removed in
// PR G (2026-06-21). Every in-tree caller now invokes
// a.as.AuthenticateClient directly (the introspect / revoke / token
// endpoints all live in internal/as/handlers).

// ---------- Metadata (RFC 8414, RFC 9728) ----------

// ASMetadata is the JSON document served at
// /.well-known/oauth-authorization-server. Field names and shape follow
// RFC 8414 section 2.
type ASMetadata = internalas.ASMetadata

// ProtectedResourceMetadata is the JSON document mandated by RFC 9728.
type ProtectedResourceMetadata = internalas.ProtectedResourceMetadata

// ASMetadataDoc builds the RFC 8414 metadata document. The result is
// deterministic across calls so handler caching is trivial. Forwards to
// as.ASMetadataDoc.
func (a *TheAuth) ASMetadataDoc() (ASMetadata, error) {
	if a.as == nil {
		return ASMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ASMetadataDoc()
}

// ProtectedResourceMetadataDoc builds the RFC 9728 document for the
// resource matching the supplied identifier. Returns an error when the
// identifier is not one of the configured resources. Forwards to
// as.ProtectedResourceMetadataDoc.
func (a *TheAuth) ProtectedResourceMetadataDoc(resourceID string) (ProtectedResourceMetadata, error) {
	if a.as == nil {
		return ProtectedResourceMetadata{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.ProtectedResourceMetadataDoc(resourceID)
}

// ---------- Authorize ----------

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
// caller should redirect to LoginURL so the user can sign in. Forwards
// to as.StartAuthorize.
func (a *TheAuth) StartAuthorize(ctx context.Context, req AuthorizeRequest, user *User) (AuthorizeResult, error) {
	if a.as == nil {
		return AuthorizeResult{}, ErrAuthorizationServerNotConfigured
	}
	return a.as.StartAuthorize(ctx, req, user)
}

// IsLoginRequired reports whether the supplied error signals the
// authorize path needs an authenticated user. Forwards to
// internalas.IsLoginRequired; both packages share the same sentinel
// pointer so existing errors.Is callers keep working.
func IsLoginRequired(err error) bool {
	return internalas.IsLoginRequired(err)
}

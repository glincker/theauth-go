package theauth

import (
	"context"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_token.go: thin forwarders for the authorization_code and
// refresh_token grants plus the client authentication helper used by
// every /oauth/token grant. PR B architecture reorg (2026-06-20) moved
// the implementations into internal/as; the exported request / response
// types are re-exported as aliases so the v2.0 public surface is
// unchanged.

// TokenRequest is the parsed form-encoded body of a POST /oauth/token
// call, plus the authenticated client extracted from the request line /
// headers.
type TokenRequest = internalas.TokenRequest

// TokenResponse is the JSON body emitted by /oauth/token on success.
type TokenResponse = internalas.TokenResponse

// ExchangeAuthorizationCode redeems a one-time authorization code for
// an access token + refresh token pair. Enforces PKCE S256,
// redirect_uri equality, audience binding (RFC 8707), and client
// authentication.
func (a *TheAuth) ExchangeAuthorizationCode(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ExchangeAuthorizationCode(ctx, req)
}

// RefreshAccessToken rotates a refresh token, returning a new access
// token + refresh token pair. The old refresh token is revoked;
// presenting it again triggers family-wide revocation per RFC 9700
// section 4.14.
func (a *TheAuth) RefreshAccessToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.RefreshAccessToken(ctx, req)
}

// authenticateClient verifies client credentials. Used by the
// /oauth/token, /oauth/revoke, and /oauth/introspect handlers as well
// as service_agent.go::MintAgentCredential (which authenticates the
// rotating client to surface ErrOAuthInvalidClient consistently).
// Forwards to the extracted as.Service.
func (a *TheAuth) authenticateClient(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error) {
	return a.as.AuthenticateClient(ctx, clientID, clientSecret)
}

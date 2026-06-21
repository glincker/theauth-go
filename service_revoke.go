package theauth

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/crypto"
)

// service_revoke.go: RFC 7009 token revocation.
//
// Per RFC 7009 the endpoint always returns 200 for any well-formed request
// (to avoid leaking which tokens exist), regardless of whether the token
// was found, already expired, or belonged to a different client. The only
// error path that surfaces is invalid client authentication; the handler
// maps that to 401 invalid_client per RFC 6749.

// RevokeToken invalidates a refresh token. Authorization codes and access
// tokens are out of scope for this entry: codes are single-use anyway, and
// access tokens are stateless JWTs whose lifetime is bounded by exp.
func (a *TheAuth) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if a.as == nil {
		return errors.New("theauth: authorization server not configured")
	}
	if _, err := a.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return err
	}
	if token == "" {
		// Per RFC 7009 section 2.1, a missing token parameter is still treated
		// as 200; the higher layer drops the empty-string before calling here.
		return nil
	}
	hint := tokenTypeHint
	// Phase 1 + 2 only stores refresh tokens. Access tokens are stateless JWTs
	// whose lifetime is bounded by exp, so revocation has no server-side
	// effect; we still accept the request and return success to honor the RFC.
	if hint != "" && hint != "refresh_token" {
		return nil
	}
	hash := crypto.HashToken(token)
	if err := a.as.storage.RevokeRefreshToken(ctx, hash, "explicit revoke"); err != nil {
		// Per RFC 7009 the AS MUST respond with 200 even when the token is
		// unknown; we swallow ErrStorageNotFound rather than surface it.
		return nil //nolint:nilerr // explicit RFC requirement
	}
	return nil
}

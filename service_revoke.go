package theauth

import (
	"context"
	"errors"
)

// service_revoke.go: thin forwarder for RFC 7009 token revocation. PR
// B architecture reorg (2026-06-20) moved the implementation into
// internal/as; the v2.0 public surface (signature, error mapping) is
// unchanged.

// RevokeToken invalidates a refresh token. Authorization codes and
// access tokens are out of scope for this entry: codes are single-use
// anyway, and access tokens are stateless JWTs whose lifetime is
// bounded by exp.
func (a *TheAuth) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if a.as == nil {
		return errors.New("theauth: authorization server not configured")
	}
	return a.as.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
}

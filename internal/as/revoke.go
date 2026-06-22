package as

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/crypto"
	obs "github.com/glincker/theauth-go/internal/observability"
)

// revoke.go: RFC 7009 token revocation.
//
// Per RFC 7009 the endpoint always returns 200 for any well-formed
// request (to avoid leaking which tokens exist), regardless of whether
// the token was found, already expired, or belonged to a different
// client. The only error path that surfaces is invalid client
// authentication; the handler maps that to 401 invalid_client per RFC
// 6749.

// RevokeToken invalidates a refresh token. Authorization codes and
// access tokens are out of scope for this entry: codes are single-use
// anyway, and access tokens are stateless JWTs whose lifetime is bounded
// by exp.
func (s *Service) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (err error) {
	if s == nil {
		return errors.New("theauth: authorization server not configured")
	}
	ctx, span := s.Hooks.StartSpan(ctx, obs.SpanOAuthRevoke)
	defer func() {
		status := obs.StatusSuccess
		if err != nil {
			status = obs.StatusError
			span.RecordError(err)
			span.SetAttributes(obs.StringAttr(obs.AttrErrorCode, errorCode(err)))
		}
		span.SetAttributes(obs.StringAttr(obs.AttrStatus, string(status)))
		span.End()
	}()
	if _, aerr := s.AuthenticateClient(ctx, clientID, clientSecret); aerr != nil {
		err = aerr
		return err
	}
	if token == "" {
		// Per RFC 7009 section 2.1, a missing token parameter is still
		// treated as 200; the higher layer drops the empty-string before
		// calling here.
		return nil
	}
	hint := tokenTypeHint
	// Phase 1 + 2 only stores refresh tokens. Access tokens are stateless
	// JWTs whose lifetime is bounded by exp, so revocation has no
	// server-side effect; we still accept the request and return success
	// to honor the RFC.
	if hint != "" && hint != "refresh_token" {
		return nil
	}
	hash := crypto.HashToken(token)
	// security re-audit L3 (2026-06-22): explicit revoke should walk the
	// entire rotation family (parent + all children) so that rotating a
	// compromised token before calling revoke does not leave the fresh
	// child alive. Mirror the reuse-detection family walk in
	// RefreshAccessToken.
	rt, err := s.Storage.RefreshTokenByHash(ctx, hash)
	if err == nil {
		// Token found: revoke the whole family then the token itself.
		_ = s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "explicit revoke")
		return nil
	}
	// Token not found (already expired, already revoked, or never issued).
	// Per RFC 7009 the AS MUST respond with 200 on unknown tokens.
	return nil
}

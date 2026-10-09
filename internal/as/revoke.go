package as

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
)

// revoke.go: RFC 7009 token revocation.
//
// Per RFC 7009 the endpoint always returns 200 for any well-formed
// request (to avoid leaking which tokens exist), regardless of whether
// the token was found, already expired, or belonged to a different
// client. The only error path that surfaces is invalid client
// authentication; the handler maps that to 401 invalid_client per RFC
// 6749.

// RevokeToken invalidates a refresh token (whole rotation family) or, when
// Config.AccessTokenRevocation is on, an access token via the jti
// denylist. Only the client the token was issued to may revoke it.
// Authorization codes are single-use anyway.
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
	client, aerr := s.AuthenticateClient(ctx, clientID, clientSecret)
	if aerr != nil {
		err = aerr
		return err
	}
	if token == "" {
		// Per RFC 7009 section 2.1, a missing token parameter is still
		// treated as 200; the higher layer drops the empty-string before
		// calling here.
		return nil
	}
	// Access tokens are JWTs (three segments); refresh tokens are opaque.
	// The hint is advisory (RFC 7009 section 2.1), so the shape decides.
	if strings.Count(token, ".") == 2 {
		s.revokeAccessToken(ctx, token, client.ClientID)
		return nil
	}
	hash := crypto.HashToken(token)
	if s.revokeOpaqueAccessToken(ctx, hash, client.ClientID) {
		return nil
	}
	if tokenTypeHint == "access_token" {
		return nil
	}
	// security re-audit L3 (2026-06-22): explicit revoke should walk the
	// entire rotation family (parent + all children) so that rotating a
	// compromised token before calling revoke does not leave the fresh
	// child alive. Mirror the reuse-detection family walk in
	// RefreshAccessToken.
	rt, err := s.Storage.RefreshTokenByHash(ctx, hash)
	if err != nil {
		// Unknown, expired or never issued: RFC 7009 still answers 200.
		err = nil
		return nil
	}
	// RFC 7009 section 2.1: the AS validates that the token was issued to
	// the authenticated client. A mismatch is answered 200 without effect
	// so a client cannot probe or kill another client's tokens.
	if rt.ClientID != client.ClientID {
		return nil
	}
	_ = s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "explicit revoke")
	return nil
}

// revokeAccessToken adds the token's jti to the denylist when the feature
// is enabled. Without it, access tokens stay stateless and the call is a
// no-op, as before. Only the issuing client may revoke.
func (s *Service) revokeAccessToken(ctx context.Context, token, clientID string) {
	if s.denylist() == nil {
		return
	}
	claims, verr := s.verifyAccessJWT(token, "", time.Now())
	if verr != nil || claims.Iss != s.Cfg.Issuer || claims.ClientID != clientID || claims.Jti == "" {
		return
	}
	_ = s.denyAccessJTI(ctx, claims.Jti, time.Unix(claims.Exp, 0))
}

// revokeOpaqueAccessToken revokes a reference access token issued to
// clientID and reports whether the token was one. Opaque tokens are stateful,
// so revocation does not depend on the jti denylist being enabled.
func (s *Service) revokeOpaqueAccessToken(ctx context.Context, hash []byte, clientID string) bool {
	store, ok := s.opaqueStore()
	if !ok {
		return false
	}
	rec, err := store.OpaqueAccessTokenByHash(ctx, hash)
	if err != nil || rec == nil {
		return false
	}
	if rec.ClientID == clientID {
		_ = store.RevokeOpaqueAccessToken(ctx, hash)
		s.purgeIntrospectCache()
	}
	return true
}

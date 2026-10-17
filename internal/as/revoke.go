package as

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
)

// revoke.go implements RFC 7009 token revocation. The endpoint answers 200 for any well-formed
// request, so it never reveals which tokens exist. Only invalid client authentication is an error
// (401 invalid_client).

// RevokeToken invalidates a refresh token family, or an access token through the jti denylist when
// AccessTokenRevocation is on. Only the client the token was issued to may revoke it.
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
		// A missing token parameter is still answered 200 (RFC 7009 section 2.1).
		return nil
	}
	// Access tokens are JWTs (three segments) and refresh tokens are opaque. The hint is advisory, so
	// the shape decides.
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
	// Explicit revoke walks the whole rotation family, parent and children, so rotating a compromised
	// token before revoking it cannot leave the fresh child alive (security re-audit L3).
	s.revokeRefreshFamily(ctx, hash, client.ClientID)
	return nil
}

// revokeRefreshFamily revokes the rotation family of the refresh token, when it belongs to
// clientID. Failures are logged, never returned (RFC 7009).
func (s *Service) revokeRefreshFamily(ctx context.Context, hash []byte, clientID string) {
	rt, err := s.Storage.RefreshTokenByHash(ctx, hash)
	if err != nil {
		if !errors.Is(err, models.ErrStorageNotFound) {
			slog.Warn("theauth: refresh token lookup failed during revoke", "err", err.Error())
		}
		return
	}
	// A token issued to another client is answered 200 without effect, so clients cannot probe or kill
	// each other's tokens (RFC 7009 section 2.1).
	if rt == nil || rt.ClientID != clientID {
		return
	}
	if err := s.Storage.RevokeRefreshTokenFamily(ctx, rt.FamilyID, "explicit revoke"); err != nil {
		slog.Warn("theauth: revoke refresh token family failed", "client_id", clientID, "err", err.Error())
	}
}

// revokeAccessToken adds the token's jti to the denylist when the feature is on. Otherwise access
// tokens stay stateless.
func (s *Service) revokeAccessToken(ctx context.Context, token, clientID string) {
	if s.denylist() == nil {
		return
	}
	claims, verr := s.verifyAccessJWT(token, "", time.Now())
	if verr != nil || claims.Iss != s.Cfg.Issuer || claims.ClientID != clientID || claims.Jti == "" {
		return
	}
	if err := s.denyAccessJTI(ctx, claims.Jti, time.Unix(claims.Exp, 0)); err != nil {
		slog.Warn("theauth: access token denylist write failed during revoke", "client_id", clientID, "err", err.Error())
	}
}

// revokeOpaqueAccessToken revokes a reference access token issued to clientID and reports whether it was one.
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
		if err := store.RevokeOpaqueAccessToken(ctx, hash); err != nil {
			slog.Warn("theauth: opaque access token revoke failed", "client_id", clientID, "err", err.Error())
		}
		s.purgeIntrospectCache()
	}
	return true
}

// touchAgentLastActive records agent activity. A failure only affects the last-active display, so
// it is logged.
func (s *Service) touchAgentLastActive(ctx context.Context, id models.ULID, at time.Time) {
	if err := s.Storage.UpdateAgentLastActive(ctx, id, at); err != nil {
		slog.Warn("theauth: agent last active update failed", "agent_id", id.String(), "err", err.Error())
	}
}

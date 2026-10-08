package as

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// hardening.go: shared helpers for the 2026-10 AS security pass:
// authorization-code hashing at rest, replay revocation, the opt-in
// access-token denylist and DPoP key-binding comparisons.

// codeStorageKey maps a presented authorization code to the value the
// storage layer keeps. Codes are 256-bit random tokens, so a plain SHA-256
// is enough: a database read yields nothing redeemable.
func codeStorageKey(code string) string {
	return hex.EncodeToString(crypto.HashToken(code))
}

// handleCodeReplay runs when a code cannot be consumed. If tokens were
// already issued from it, the whole family is revoked (RFC 6749 section
// 4.1.2) and, with the denylist on, the matching access tokens too. A code
// that never existed is a no-op.
func (s *Service) handleCodeReplay(ctx context.Context, codeKey string) {
	rs, ok := s.Storage.(AuthCodeReplayStorage)
	if !ok {
		return
	}
	jtis, err := rs.RevokeRefreshTokensByAuthCode(ctx, codeKey, "authorization code replay")
	if err != nil || len(jtis) == 0 {
		return
	}
	exp := time.Now().Add(s.Cfg.AccessTokenTTL)
	for _, j := range jtis {
		_ = s.denyAccessJTI(ctx, j, exp)
	}
	s.Audit.EmitAudit(ctx, "oauth.code_replay_revoked", models.TargetRef{Type: "oauth_code", ID: codeKey[:12]},
		map[string]any{"tokens_revoked": len(jtis)})
}

// denylist returns the denylist backend when the feature is enabled and
// supported by the storage adapter.
func (s *Service) denylist() AccessTokenDenylistStorage {
	if s == nil || !s.Cfg.AccessTokenRevocation {
		return nil
	}
	d, _ := s.Storage.(AccessTokenDenylistStorage)
	return d
}

func (s *Service) denyAccessJTI(ctx context.Context, jti string, exp time.Time) error {
	d := s.denylist()
	if d == nil || jti == "" {
		return nil
	}
	err := d.DenyAccessToken(ctx, jti, exp)
	if err == nil {
		s.purgeIntrospectCache()
	}
	return err
}

// accessJTIRevoked reports whether jti is denied. Storage errors fail
// closed (treated as revoked) so an outage cannot resurrect a revoked
// token.
func (s *Service) accessJTIRevoked(ctx context.Context, jti string) bool {
	d := s.denylist()
	if d == nil || jti == "" {
		return false
	}
	denied, err := d.IsAccessTokenDenied(ctx, jti)
	return err != nil || denied
}

// jktEqual compares two JWK thumbprints in constant time.
func jktEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// cnfJKT extracts cnf.jkt from decoded JWT extra claims.
func cnfJKT(extra map[string]any) string {
	m, ok := extra["cnf"].(map[string]any)
	if !ok {
		return ""
	}
	j, _ := m["jkt"].(string)
	return j
}

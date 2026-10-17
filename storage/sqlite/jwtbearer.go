package sqlite

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.JWTBearerStorage = (*Store)(nil)

// InsertJTI records a jti for RFC 7523 replay protection. It returns
// ErrStorageNotFound when the jti is already recorded and unexpired (the
// JWTBearerStorage duplicate signal). One upsert statement decides the winner:
// an expired row is overwritten, a live row blocks the insert, so concurrent
// presentations of the same jti produce exactly one success.
func (s *Store) InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	now := toMicro(time.Now())
	res, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_jwt_bearer_jtis (jti, expires_at) VALUES (?, ?)
ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at
WHERE theauth_jwt_bearer_jtis.expires_at < ?`), jti, toMicro(expiresAt), now)
	if err != nil {
		return wrap("insert jti", err)
	}
	return requireRows("insert jti", res)
}

// SweepExpiredJTIs removes every jti that expired before the given time.
func (s *Store) SweepExpiredJTIs(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_jwt_bearer_jtis WHERE expires_at < ?`), toMicro(before))
	return wrap("sweep jtis", err)
}

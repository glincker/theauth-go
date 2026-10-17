package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// as_opaque.go: opaque (reference) access tokens over migration 0026.

func (s *Store) InsertOpaqueAccessToken(ctx context.Context, t theauth.OpaqueAccessToken) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_oauth_opaque_access_tokens (hash, jti, client_id, claims, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)`),
		t.Hash, t.JTI, t.ClientID, nonNilBytes(t.Claims), toMicro(t.IssuedAt), toMicro(t.ExpiresAt))
	return wrap("insert opaque access token", err)
}

func (s *Store) OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*theauth.OpaqueAccessToken, error) {
	var (
		out             theauth.OpaqueAccessToken
		issued, expires int64
		revoked         sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
SELECT hash, jti, client_id, claims, issued_at, expires_at, revoked_at
FROM theauth_oauth_opaque_access_tokens WHERE hash = ?`), hash).Scan(
		&out.Hash, &out.JTI, &out.ClientID, &out.Claims, &issued, &expires, &revoked)
	if err != nil {
		return nil, notFoundOr("opaque access token by hash", err)
	}
	out.IssuedAt = fromMicro(issued)
	out.ExpiresAt = fromMicro(expires)
	out.RevokedAt = fromNullMicro(revoked)
	return &out, nil
}

// RevokeOpaqueAccessToken implements theauth.OpaqueTokenStorage. Revoking an
// unknown or already revoked token is not an error, and the first revocation
// time is kept.
func (s *Store) RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_oauth_opaque_access_tokens SET revoked_at = ? WHERE hash = ? AND revoked_at IS NULL`),
		toMicro(time.Now()), hash)
	return wrap("revoke opaque access token", err)
}

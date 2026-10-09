package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// opaque.go: OpaqueTokenStorage over migration 0021.

var _ theauth.OpaqueTokenStorage = (*Store)(nil)

// InsertOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) InsertOpaqueAccessToken(ctx context.Context, t theauth.OpaqueAccessToken) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO oauth_opaque_access_tokens (hash, jti, client_id, claims, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		t.Hash, t.JTI, t.ClientID, t.Claims, timeUTC(t.IssuedAt), timeUTC(t.ExpiresAt))
	return err
}

// OpaqueAccessTokenByHash satisfies OpaqueTokenStorage.
func (s *Store) OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*theauth.OpaqueAccessToken, error) {
	var (
		out             theauth.OpaqueAccessToken
		issued, expires time.Time
		revoked         sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT hash, jti, client_id, claims, issued_at, expires_at, revoked_at
FROM oauth_opaque_access_tokens WHERE hash = ?`, hash,
	).Scan(&out.Hash, &out.JTI, &out.ClientID, &out.Claims, &issued, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, theauth.ErrStorageNotFound
	}
	if err != nil {
		return nil, err
	}
	out.IssuedAt = issued.UTC()
	out.ExpiresAt = expires.UTC()
	out.RevokedAt = nullTimeToPtr(revoked)
	return &out, nil
}

// RevokeOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oauth_opaque_access_tokens SET revoked_at = ? WHERE hash = ? AND revoked_at IS NULL`,
		timeUTC(time.Now()), hash)
	return err
}

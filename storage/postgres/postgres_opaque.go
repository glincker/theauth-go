package postgres

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_opaque.go: OpaqueTokenStorage over migration 0021.

var _ theauth.OpaqueTokenStorage = (*Store)(nil)

// InsertOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) InsertOpaqueAccessToken(ctx context.Context, t theauth.OpaqueAccessToken) error {
	const q = `
INSERT INTO oauth_opaque_access_tokens (hash, jti, client_id, claims, issued_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.pool.Exec(ctx, q, t.Hash, t.JTI, t.ClientID, t.Claims, timeToTs(t.IssuedAt), timeToTs(t.ExpiresAt))
	return err
}

// OpaqueAccessTokenByHash satisfies OpaqueTokenStorage.
func (s *Store) OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*theauth.OpaqueAccessToken, error) {
	const q = `
SELECT hash, jti, client_id, claims, issued_at, expires_at, revoked_at
FROM oauth_opaque_access_tokens WHERE hash = $1`
	var (
		out                     theauth.OpaqueAccessToken
		issued, expires, revoke pgtype.Timestamptz
	)
	err := s.pool.QueryRow(ctx, q, hash).Scan(&out.Hash, &out.JTI, &out.ClientID, &out.Claims, &issued, &expires, &revoke)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, theauth.ErrStorageNotFound
		}
		return nil, err
	}
	out.IssuedAt = tsToTime(issued)
	out.ExpiresAt = tsToTime(expires)
	out.RevokedAt = tsToTimePtr(revoke)
	return &out, nil
}

// RevokeOpaqueAccessToken satisfies OpaqueTokenStorage.
func (s *Store) RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error {
	const q = `UPDATE oauth_opaque_access_tokens SET revoked_at = now() WHERE hash = $1 AND revoked_at IS NULL`
	_, err := s.pool.Exec(ctx, q, hash)
	return err
}

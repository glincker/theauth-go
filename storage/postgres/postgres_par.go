package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5"
)

// postgres_par.go: RFC 9126 Pushed Authorization Requests storage adapter.

// InsertPushedRequest stores a pushed authorization request.
// The requestURI is the full urn: string; payload is the JSON-encoded
// AuthorizeRequest; expiresAt is the absolute expiry timestamp.
func (s *Store) InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error {
	const q = `
INSERT INTO pushed_authorization_requests (request_uri, payload, expires_at)
VALUES ($1, $2, $3)`
	_, err := s.pool.Exec(ctx, q, requestURI, payload, timeToTs(expiresAt))
	return err
}

// ConsumePushedRequest atomically marks the row as consumed and returns
// the payload. Returns ErrNotFound when:
//   - the request_uri does not exist
//   - the row has already been consumed (consumed_at IS NOT NULL)
//   - the row is expired (expires_at <= now)
func (s *Store) ConsumePushedRequest(ctx context.Context, requestURI string) ([]byte, error) {
	const q = `
UPDATE pushed_authorization_requests
   SET consumed_at = NOW()
 WHERE request_uri   = $1
   AND consumed_at   IS NULL
   AND expires_at    > NOW()
RETURNING payload`
	var payload []byte
	err := s.pool.QueryRow(ctx, q, requestURI).Scan(&payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return payload, nil
}

package sqlite

import (
	"context"
	"time"
)

// as_par.go: RFC 9126 pushed authorization requests over migration 0025.

// InsertPushedRequest stores a pushed authorization request. requestURI is the
// full urn: string, payload the JSON encoded AuthorizeRequest.
func (s *Store) InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_pushed_authorization_requests (request_uri, payload, expires_at) VALUES (?, ?, ?)`),
		requestURI, nonNilBytes(payload), toMicro(expiresAt))
	return wrap("insert pushed request", err)
}

// ConsumePushedRequest atomically marks the row consumed and returns its
// payload. It returns ErrStorageNotFound when the request_uri is unknown,
// already consumed, or expired. The conditional UPDATE is the single winner.
func (s *Store) ConsumePushedRequest(ctx context.Context, requestURI string) ([]byte, error) {
	var payload []byte
	now := toMicro(time.Now())
	err := s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_pushed_authorization_requests SET consumed_at = ?
WHERE request_uri = ? AND consumed_at IS NULL AND expires_at > ?
RETURNING payload`), now, requestURI, now).Scan(&payload)
	if err != nil {
		return nil, notFoundOr("consume pushed request", err)
	}
	return payload, nil
}

var _ interface {
	InsertPushedRequest(ctx context.Context, requestURI string, payload []byte, expiresAt time.Time) error
	ConsumePushedRequest(ctx context.Context, requestURI string) ([]byte, error)
} = (*Store)(nil)

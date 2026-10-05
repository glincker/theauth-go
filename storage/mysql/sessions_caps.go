package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

var (
	_ theauth.SessionManagementStorage = (*Store)(nil)
	_ theauth.SessionLinkStorage       = (*Store)(nil)
)

const liveSession = `revoked_at IS NULL AND expires_at > ?`

// rowExists tells a no-op update (value unchanged) from a missing row, since
// MySQL reports changed rows rather than matched rows by default.
func (s *Store) rowExists(ctx context.Context, table string, id theauth.ULID) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM `+table+` WHERE id = ?`, ulidToBytes(id)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) execOnRow(ctx context.Context, op, table string, id theauth.ULID, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("mysql: %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: %s: %w", op, err)
	}
	if n > 0 {
		return nil
	}
	ok, err := s.rowExists(ctx, table, id)
	if err != nil {
		return fmt.Errorf("mysql: %s: %w", op, err)
	}
	if !ok {
		return fmt.Errorf("mysql: %s: %w", op, storage.ErrNotFound)
	}
	return nil
}

func rowsCount(op string, res sql.Result, err error) (int, error) {
	if err != nil {
		return 0, fmt.Errorf("mysql: %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mysql: %s: %w", op, err)
	}
	return int(n), nil
}

// ListUserSessions returns the user's live sessions, newest first.
func (s *Store) ListUserSessions(ctx context.Context, userID theauth.ULID) ([]theauth.Session, error) {
	rows, err := s.db.QueryContext(ctx, selectSessionColumns+
		` WHERE user_id = ? AND `+liveSession+` ORDER BY created_at DESC, id DESC`,
		ulidToBytes(userID), timeUTC(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("mysql: list user sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: list user sessions: %w", err)
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: list user sessions: %w", err)
	}
	return out, nil
}

// TouchSession advances last-seen time and never moves it backwards.
func (s *Store) TouchSession(ctx context.Context, id theauth.ULID, at time.Time) error {
	at = timeUTC(at)
	return s.execOnRow(ctx, "touch session", "sessions", id, `
UPDATE sessions SET last_seen_at = IF(last_seen_at IS NULL OR last_seen_at < ?, ?, last_seen_at) WHERE id = ?`,
		at, at, ulidToBytes(id))
}

// RevokeOtherUserSessions revokes the user's live sessions except keep and returns the count.
func (s *Store) RevokeOtherUserSessions(ctx context.Context, userID, keep theauth.ULID) (int, error) {
	now := timeUTC(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND `+liveSession,
		now, ulidToBytes(userID), ulidToBytes(keep), now)
	return rowsCount("revoke other user sessions", res, err)
}

// RevokeSessionsByCredential revokes every live session bound to credentialID and returns the count.
func (s *Store) RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error) {
	now := timeUTC(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE credential_id = ? AND `+liveSession,
		now, credentialID, now)
	return rowsCount("revoke sessions by credential", res, err)
}

// SetSessionElevatedUntil sets or clears the step-up window of one session.
func (s *Store) SetSessionElevatedUntil(ctx context.Context, id theauth.ULID, until *time.Time) error {
	return s.execOnRow(ctx, "set session elevated until", "sessions", id,
		`UPDATE sessions SET elevated_until = ? WHERE id = ?`, timePtrToNull(until), ulidToBytes(id))
}

// CreateSessionLink stores a single-use session link.
func (s *Store) CreateSessionLink(ctx context.Context, l theauth.SessionLink) error {
	created := l.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO session_links (id, user_id, token_hash, credential_id, session_ttl, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(l.ID), ulidToBytes(l.UserID), l.TokenHash, l.CredentialID, int64(l.SessionTTL),
		timeUTC(created), timeUTC(l.ExpiresAt))
	if err != nil {
		return fmt.Errorf("mysql: create session link: %w", err)
	}
	return nil
}

// ConsumeSessionLink atomically marks an unused, unexpired link used and returns it, else ErrNotFound.
func (s *Store) ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*theauth.SessionLink, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql: consume session link: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
UPDATE session_links SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		timeUTC(now), tokenHash, timeUTC(now))
	if err != nil {
		return nil, fmt.Errorf("mysql: consume session link: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("mysql: consume session link: %w", storage.ErrNotFound)
	}
	var (
		idB, userB, cred           = []byte(nil), []byte(nil), ""
		ttl                        int64
		created, expires, consumed time.Time
	)
	err = tx.QueryRowContext(ctx, `
SELECT id, user_id, credential_id, session_ttl, created_at, expires_at, consumed_at FROM session_links WHERE token_hash = ?`,
		tokenHash).Scan(&idB, &userB, &cred, &ttl, &created, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("mysql: consume session link: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mysql: consume session link: %w", err)
	}
	c := consumed.UTC()
	return &theauth.SessionLink{
		ID: bytesToULID(idB), UserID: bytesToULID(userB), TokenHash: tokenHash, CredentialID: cred,
		SessionTTL: time.Duration(ttl), CreatedAt: created.UTC(), ExpiresAt: expires.UTC(), ConsumedAt: &c,
	}, nil
}

package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go"
)

var (
	_ theauth.SessionManagementStorage = (*Store)(nil)
	_ theauth.SessionLinkStorage       = (*Store)(nil)
)

const liveSession = `revoked_at IS NULL AND expires_at > ?`

// ListUserSessions returns the user's live sessions, newest first.
func (s *Store) ListUserSessions(ctx context.Context, userID theauth.ULID) ([]theauth.Session, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+sessionCols+
		` FROM theauth_sessions WHERE user_id = ? AND `+liveSession+` ORDER BY created_at DESC, id DESC`),
		idStr(userID), toMicro(time.Now()))
	if err != nil {
		return nil, wrap("list user sessions", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, wrap("list user sessions", err)
		}
		out = append(out, sess)
	}
	return out, wrap("list user sessions", rows.Err())
}

// TouchSession advances last-seen time and never moves it backwards.
func (s *Store) TouchSession(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_sessions SET last_seen_at = MAX(last_seen_at, ?) WHERE id = ?`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("touch session", err)
	}
	return requireRows("touch session", res)
}

// RevokeOtherUserSessions revokes the user's live sessions except keep and returns the count.
func (s *Store) RevokeOtherUserSessions(ctx context.Context, userID, keep theauth.ULID) (int, error) {
	now := toMicro(time.Now())
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND `+liveSession),
		now, idStr(userID), idStr(keep), now)
	return rowsOrErr("revoke other user sessions", res, err)
}

// RevokeSessionsByCredential revokes every live session bound to credentialID and returns the count.
func (s *Store) RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error) {
	now := toMicro(time.Now())
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_sessions SET revoked_at = ? WHERE credential_id = ? AND `+liveSession),
		now, credentialID, now)
	return rowsOrErr("revoke sessions by credential", res, err)
}

// SetSessionElevatedUntil sets or clears the step-up window of one session.
func (s *Store) SetSessionElevatedUntil(ctx context.Context, id theauth.ULID, until *time.Time) error {
	res, err := s.db.ExecContext(ctx,
		s.q(`UPDATE theauth_sessions SET elevated_until = ? WHERE id = ?`), toNullMicro(until), idStr(id))
	if err != nil {
		return wrap("set session elevated until", err)
	}
	return requireRows("set session elevated until", res)
}

// CreateSessionLink stores a single-use session link.
func (s *Store) CreateSessionLink(ctx context.Context, l theauth.SessionLink) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_session_links (id, user_id, token_hash, credential_id, session_ttl, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`),
		idStr(l.ID), idStr(l.UserID), l.TokenHash, l.CredentialID, int64(l.SessionTTL),
		toMicro(orNow(l.CreatedAt)), toMicro(l.ExpiresAt))
	return wrap("create session link", err)
}

// ConsumeSessionLink atomically marks an unused, unexpired link used and returns it, else ErrStorageNotFound.
func (s *Store) ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*theauth.SessionLink, error) {
	var (
		id, userID, cred string
		ttl, created     int64
		expires, used    int64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_session_links SET consumed_at = ?
WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?
RETURNING id, user_id, credential_id, session_ttl, created_at, expires_at, consumed_at`),
		toMicro(now), tokenHash, toMicro(now)).Scan(&id, &userID, &cred, &ttl, &created, &expires, &used)
	if err != nil {
		return nil, notFoundOr("consume session link", err)
	}
	lid, err := parseID(id)
	if err != nil {
		return nil, wrap("consume session link", err)
	}
	uid, err := parseID(userID)
	if err != nil {
		return nil, wrap("consume session link", err)
	}
	consumed := fromMicro(used)
	return &theauth.SessionLink{
		ID: lid, UserID: uid, TokenHash: tokenHash, CredentialID: cred, SessionTTL: time.Duration(ttl),
		CreatedAt: fromMicro(created), ExpiresAt: fromMicro(expires), ConsumedAt: &consumed,
	}, nil
}

func rowsOrErr(op string, res sql.Result, err error) (int, error) {
	if err != nil {
		return 0, wrap(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrap(op, err)
	}
	return int(n), nil
}

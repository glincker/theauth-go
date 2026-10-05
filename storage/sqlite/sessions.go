package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go"
)

const sessionCols = `id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level`

func scanSession(r scanner) (theauth.Session, error) {
	var (
		id, userID, ua, ip, level string
		hash                      []byte
		created, expires          int64
		revoked                   sql.NullInt64
	)
	if err := r.Scan(&id, &userID, &hash, &ua, &ip, &created, &expires, &revoked, &level); err != nil {
		return theauth.Session{}, err
	}
	sid, err := parseID(id)
	if err != nil {
		return theauth.Session{}, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return theauth.Session{}, err
	}
	return theauth.Session{
		ID:        sid,
		UserID:    uid,
		TokenHash: hash,
		UserAgent: ua,
		IP:        ip,
		CreatedAt: fromMicro(created),
		ExpiresAt: fromMicro(expires),
		RevokedAt: fromNullMicro(revoked),
		AuthLevel: level,
	}, nil
}

// CreateSession inserts a session, defaulting AuthLevel to full.
func (s *Store) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	level := sess.AuthLevel
	if level == "" {
		level = theauth.AuthLevelFull
	}
	row := s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING `+sessionCols),
		idStr(sess.ID), idStr(sess.UserID), sess.TokenHash, sess.UserAgent, sess.IP,
		toMicro(orNow(sess.CreatedAt)), toMicro(sess.ExpiresAt), level,
	)
	out, err := scanSession(row)
	if err != nil {
		return theauth.Session{}, wrap("create session", err)
	}
	return out, nil
}

// CreateSessionWithAuthLevel is CreateSession; the level is read from sess.AuthLevel.
func (s *Store) CreateSessionWithAuthLevel(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.CreateSession(ctx, sess)
}

// SessionByTokenHash returns the session for a token hash, including revoked and expired ones.
func (s *Store) SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+sessionCols+` FROM theauth_sessions WHERE token_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("session by token hash", err)
	}
	return &sess, nil
}

// SessionByID returns the session with the given ID.
func (s *Store) SessionByID(ctx context.Context, id theauth.ULID) (*theauth.Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+sessionCols+` FROM theauth_sessions WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("session by id", err)
	}
	return &sess, nil
}

// RevokeSession marks a session revoked and keeps the first revocation time on repeat calls.
func (s *Store) RevokeSession(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		s.q(`UPDATE theauth_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`),
		toMicro(time.Now()), idStr(id))
	if err != nil {
		return wrap("revoke session", err)
	}
	return requireRows("revoke session", res)
}

// RevokeUserSessions revokes every active session of a user.
func (s *Store) RevokeUserSessions(ctx context.Context, userID theauth.ULID) error {
	_, err := s.db.ExecContext(ctx,
		s.q(`UPDATE theauth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`),
		toMicro(time.Now()), idStr(userID))
	return wrap("revoke user sessions", err)
}

// UpdateSessionAuthLevel rewrites one session's auth level.
func (s *Store) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	res, err := s.db.ExecContext(ctx,
		s.q(`UPDATE theauth_sessions SET auth_level = ? WHERE id = ?`), level, idStr(id))
	if err != nil {
		return wrap("update session auth level", err)
	}
	return requireRows("update session auth level", res)
}

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

const sessionBaseCols = `id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level, last_seen_at, elevated_until, credential_id`

const sessionAuthCols = sessionBaseCols + `, auth_methods, auth_time`

// sessionAuthProbeKey keys the cached column probe; real cache keys are SQL text.
const sessionAuthProbeKey = "\x00probe:session-auth-columns"

// hasSessionAuthCols reports whether sessions has the migration 0034 auth_methods and
// auth_time columns. Hosts that skip newer migrations read sessions with no auth record.
// The probe runs once per Store; a failed probe is not cached.
func (s *Store) hasSessionAuthCols(ctx context.Context) (bool, error) {
	if v, ok := s.cache.Load(sessionAuthProbeKey); ok {
		return v.(bool), nil
	}
	rows, err := s.db.QueryContext(ctx, s.q(`PRAGMA table_info(theauth_sessions)`))
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	var found int
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			dflt       sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &primaryKey); err != nil {
			return false, err
		}
		if name == "auth_methods" || name == "auth_time" {
			found++
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	has := found == 2
	s.cache.Store(sessionAuthProbeKey, has)
	return has, nil
}

// sessionCols returns the session column list for the current schema, and
// whether it includes the auth record columns.
func (s *Store) sessionCols(ctx context.Context) (string, bool, error) {
	has, err := s.hasSessionAuthCols(ctx)
	if err != nil {
		return "", false, err
	}
	if has {
		return sessionAuthCols, true, nil
	}
	return sessionBaseCols, false, nil
}

func scanSession(r scanner, withAuth bool) (theauth.Session, error) {
	var (
		id, userID, ua, ip, level, cred string
		hash                            []byte
		created, expires, seen          int64
		revoked, elevated, authTime     sql.NullInt64
		methodsJSON                     sql.NullString
	)
	dest := []any{&id, &userID, &hash, &ua, &ip, &created, &expires, &revoked, &level, &seen, &elevated, &cred}
	if withAuth {
		dest = append(dest, &methodsJSON, &authTime)
	}
	if err := r.Scan(dest...); err != nil {
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
	var lastSeen time.Time
	if seen != 0 {
		lastSeen = fromMicro(seen)
	}
	var methods []string
	if methodsJSON.Valid && methodsJSON.String != "" {
		if err := json.Unmarshal([]byte(methodsJSON.String), &methods); err != nil {
			return theauth.Session{}, fmt.Errorf("decode session auth methods: %w", err)
		}
	}
	var authAt time.Time
	if authTime.Valid {
		authAt = fromMicro(authTime.Int64)
	}
	return theauth.Session{
		AuthMethods:   methods,
		AuthTime:      authAt,
		ID:            sid,
		UserID:        uid,
		TokenHash:     hash,
		UserAgent:     ua,
		IP:            ip,
		CreatedAt:     fromMicro(created),
		ExpiresAt:     fromMicro(expires),
		RevokedAt:     fromNullMicro(revoked),
		AuthLevel:     level,
		ElevatedUntil: fromNullMicro(elevated),
		CredentialID:  cred,
		LastSeenAt:    lastSeen,
	}, nil
}

// CreateSession inserts a session, defaulting AuthLevel to full.
func (s *Store) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	level := sess.AuthLevel
	if level == "" {
		level = theauth.AuthLevelFull
	}
	cols, withAuth, err := s.sessionCols(ctx)
	if err != nil {
		return theauth.Session{}, wrap("create session", err)
	}
	insertCols := `id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level, last_seen_at, credential_id`
	marks := `?, ?, ?, ?, ?, ?, ?, ?, ?, ?`
	args := []any{
		idStr(sess.ID), idStr(sess.UserID), sess.TokenHash, sess.UserAgent, sess.IP,
		toMicro(orNow(sess.CreatedAt)), toMicro(sess.ExpiresAt), level, lastSeenMicro(sess.LastSeenAt), sess.CredentialID,
	}
	if withAuth {
		insertCols += `, auth_methods, auth_time`
		marks += `, ?, ?`
		args = append(args, methodsJSONVal(sess.AuthMethods), authTimeVal(sess.AuthTime))
	}
	row := s.db.QueryRowContext(ctx, s.q(`INSERT INTO theauth_sessions (`+insertCols+`) VALUES (`+marks+`) RETURNING `+cols), args...)
	out, err := scanSession(row, withAuth)
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
	cols, withAuth, err := s.sessionCols(ctx)
	if err != nil {
		return nil, wrap("session by token hash", err)
	}
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+cols+` FROM theauth_sessions WHERE token_hash = ?`), hash), withAuth)
	if err != nil {
		return nil, notFoundOr("session by token hash", err)
	}
	if err := s.attachActiveOrg(ctx, &sess); err != nil {
		return nil, wrap("session by token hash", err)
	}
	return &sess, nil
}

// SessionByID returns the session with the given ID.
func (s *Store) SessionByID(ctx context.Context, id theauth.ULID) (*theauth.Session, error) {
	cols, withAuth, err := s.sessionCols(ctx)
	if err != nil {
		return nil, wrap("session by id", err)
	}
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+cols+` FROM theauth_sessions WHERE id = ?`), idStr(id)), withAuth)
	if err != nil {
		return nil, notFoundOr("session by id", err)
	}
	if err := s.attachActiveOrg(ctx, &sess); err != nil {
		return nil, wrap("session by id", err)
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

func lastSeenMicro(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return toMicro(t)
}

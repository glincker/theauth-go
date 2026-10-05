package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	_ theauth.SessionManagementStorage = (*Store)(nil)
	_ theauth.SessionLinkStorage       = (*Store)(nil)
)

const sessionCols = `id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at,
auth_level, active_organization_id, last_seen_at, elevated_until, credential_id`

const liveSession = `revoked_at IS NULL AND expires_at > $%d`

func scanSession(r pgx.Row) (theauth.Session, error) {
	var (
		id, userID, org         pgtype.UUID
		hash                    []byte
		ua, level, cred         string
		ip                      *netip.Addr
		created, expires        pgtype.Timestamptz
		revoked, seen, elevated pgtype.Timestamptz
	)
	if err := r.Scan(&id, &userID, &hash, &ua, &ip, &created, &expires, &revoked, &level, &org, &seen, &elevated, &cred); err != nil {
		return theauth.Session{}, err
	}
	s := theauth.Session{
		ID: pgUUIDToULID(id), UserID: pgUUIDToULID(userID), TokenHash: hash, UserAgent: ua, IP: pgIPToStr(ip),
		CreatedAt: tsToTime(created), ExpiresAt: tsToTime(expires), RevokedAt: tsToTimePtr(revoked),
		AuthLevel: level, ElevatedUntil: tsToTimePtr(elevated), CredentialID: cred,
	}
	if seen.Valid {
		s.LastSeenAt = seen.Time
	}
	if org.Valid {
		oid := pgUUIDToULID(org)
		s.ActiveOrganizationID = &oid
	}
	return s, nil
}

func zeroToNullTs(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return timeToTs(t)
}

func (s *Store) insertSession(ctx context.Context, sess theauth.Session, level string) (theauth.Session, error) {
	if level == "" {
		level = theauth.AuthLevelFull
	}
	out, err := scanSession(s.pool.QueryRow(ctx, `
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level, last_seen_at, credential_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING `+sessionCols,
		ulidToPgUUID(sess.ID), ulidToPgUUID(sess.UserID), sess.TokenHash, sess.UserAgent, ipStrToPg(sess.IP),
		timeToTs(sess.CreatedAt), timeToTs(sess.ExpiresAt), level, zeroToNullTs(sess.LastSeenAt), sess.CredentialID))
	if err != nil {
		return theauth.Session{}, fmt.Errorf("postgres: create session: %w", err)
	}
	return out, nil
}

// CreateSession inserts a session with the default full auth level.
func (s *Store) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.insertSession(ctx, sess, theauth.AuthLevelFull)
}

// CreateSessionWithAuthLevel inserts a session with its own auth level.
func (s *Store) CreateSessionWithAuthLevel(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.insertSession(ctx, sess, sess.AuthLevel)
}

func (s *Store) sessionWhere(ctx context.Context, where string, arg any) (*theauth.Session, error) {
	sess, err := scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE `+where, arg))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get session: %w", err)
	}
	return &sess, nil
}

// SessionByTokenHash returns the session with the given token hash.
func (s *Store) SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error) {
	return s.sessionWhere(ctx, `token_hash = $1`, hash)
}

// SessionByID returns the session with the given ID.
func (s *Store) SessionByID(ctx context.Context, id theauth.ULID) (*theauth.Session, error) {
	return s.sessionWhere(ctx, `id = $1`, ulidToPgUUID(id))
}

// ListUserSessions returns the user's live sessions, newest first.
func (s *Store) ListUserSessions(ctx context.Context, userID theauth.ULID) ([]theauth.Session, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sessionCols+
		` FROM sessions WHERE user_id = $1 AND `+fmt.Sprintf(liveSession, 2)+` ORDER BY created_at DESC, id DESC`,
		ulidToPgUUID(userID), time.Now())
	if err != nil {
		return nil, fmt.Errorf("postgres: list user sessions: %w", err)
	}
	defer rows.Close()
	var out []theauth.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: list user sessions: %w", err)
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list user sessions: %w", err)
	}
	return out, nil
}

func requireOne(op string, n int64) error {
	if n == 0 {
		return fmt.Errorf("postgres: %s: %w", op, storage.ErrNotFound)
	}
	return nil
}

// TouchSession advances last-seen time and never moves it backwards.
func (s *Store) TouchSession(ctx context.Context, id theauth.ULID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = GREATEST(last_seen_at, $2) WHERE id = $1`,
		ulidToPgUUID(id), at)
	if err != nil {
		return fmt.Errorf("postgres: touch session: %w", err)
	}
	return requireOne("touch session", tag.RowsAffected())
}

// RevokeOtherUserSessions revokes the user's live sessions except keep and returns the count.
func (s *Store) RevokeOtherUserSessions(ctx context.Context, userID, keep theauth.ULID) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = $3 WHERE user_id = $1 AND id <> $2 AND `+fmt.Sprintf(liveSession, 3),
		ulidToPgUUID(userID), ulidToPgUUID(keep), time.Now())
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke other user sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RevokeSessionsByCredential revokes every live session bound to credentialID and returns the count.
func (s *Store) RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE credential_id = $1 AND `+fmt.Sprintf(liveSession, 2),
		credentialID, time.Now())
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke sessions by credential: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SetSessionElevatedUntil sets or clears the step-up window of one session.
func (s *Store) SetSessionElevatedUntil(ctx context.Context, id theauth.ULID, until *time.Time) error {
	var ts pgtype.Timestamptz
	if until != nil {
		ts = timeToTs(*until)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET elevated_until = $2 WHERE id = $1`, ulidToPgUUID(id), ts)
	if err != nil {
		return fmt.Errorf("postgres: set session elevated until: %w", err)
	}
	return requireOne("set session elevated until", tag.RowsAffected())
}

// CreateSessionLink stores a single-use session link.
func (s *Store) CreateSessionLink(ctx context.Context, l theauth.SessionLink) error {
	created := l.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO session_links (id, user_id, token_hash, credential_id, session_ttl, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ulidToPgUUID(l.ID), ulidToPgUUID(l.UserID), l.TokenHash, l.CredentialID, int64(l.SessionTTL), created, l.ExpiresAt)
	if err != nil {
		return fmt.Errorf("postgres: create session link: %w", err)
	}
	return nil
}

// ConsumeSessionLink atomically marks an unused, unexpired link used and returns it, else ErrNotFound.
func (s *Store) ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*theauth.SessionLink, error) {
	var (
		id, userID                 pgtype.UUID
		cred                       string
		ttl                        int64
		created, expires, consumed pgtype.Timestamptz
	)
	err := s.pool.QueryRow(ctx, `
UPDATE session_links SET consumed_at = $2
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
RETURNING id, user_id, credential_id, session_ttl, created_at, expires_at, consumed_at`,
		tokenHash, now).Scan(&id, &userID, &cred, &ttl, &created, &expires, &consumed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("postgres: consume session link: %w", storage.ErrNotFound)
		}
		return nil, fmt.Errorf("postgres: consume session link: %w", err)
	}
	return &theauth.SessionLink{
		ID: pgUUIDToULID(id), UserID: pgUUIDToULID(userID), TokenHash: tokenHash, CredentialID: cred,
		SessionTTL: time.Duration(ttl), CreatedAt: tsToTime(created), ExpiresAt: tsToTime(expires),
		ConsumedAt: tsToTimePtr(consumed),
	}, nil
}

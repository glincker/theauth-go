package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func scanSession(row interface {
	Scan(dest ...interface{}) error
}) (theauth.Session, error) {
	var (
		idB, userIDB         []byte
		tokenHash            []byte
		userAgent            string
		ip                   sql.NullString
		createdAt, expiresAt time.Time
		revokedAt            sql.NullTime
		authLevel            string
		activeOrgIDB         []byte
	)
	err := row.Scan(
		&idB, &userIDB, &tokenHash,
		&userAgent, &ip,
		&createdAt, &expiresAt, &revokedAt,
		&authLevel, &activeOrgIDB,
	)
	if err != nil {
		return theauth.Session{}, err
	}
	sess := theauth.Session{
		ID:        bytesToULID(idB),
		UserID:    bytesToULID(userIDB),
		TokenHash: tokenHash,
		UserAgent: userAgent,
		IP:        nullStringScan(ip),
		CreatedAt: createdAt.UTC(),
		ExpiresAt: expiresAt.UTC(),
		RevokedAt: nullTimeToPtr(revokedAt),
		AuthLevel: authLevel,
	}
	if len(activeOrgIDB) > 0 {
		id := bytesToULID(activeOrgIDB)
		sess.ActiveOrganizationID = &id
	}
	return sess, nil
}

const selectSessionColumns = `
SELECT id, user_id, token_hash, user_agent, ip, created_at, expires_at,
       revoked_at, auth_level, active_organization_id
FROM sessions`

func (s *Store) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	level := sess.AuthLevel
	if level == "" {
		level = theauth.AuthLevelFull
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(sess.ID),
		ulidToBytes(sess.UserID),
		sess.TokenHash,
		sess.UserAgent,
		nullStringVal(sess.IP),
		timeUTC(sess.CreatedAt),
		timeUTC(sess.ExpiresAt),
		level,
	)
	if err != nil {
		return theauth.Session{}, err
	}
	got, err := s.sessionByID(ctx, sess.ID)
	if err != nil {
		return theauth.Session{}, err
	}
	return *got, nil
}

func (s *Store) CreateSessionWithAuthLevel(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.CreateSession(ctx, sess)
}

func (s *Store) sessionByID(ctx context.Context, id theauth.ULID) (*theauth.Session, error) {
	row := s.db.QueryRowContext(ctx,
		selectSessionColumns+` WHERE id = ?`,
		ulidToBytes(id),
	)
	sess, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &sess, nil
}

func (s *Store) SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error) {
	row := s.db.QueryRowContext(ctx,
		selectSessionColumns+` WHERE token_hash = ?`,
		hash,
	)
	sess, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &sess, nil
}

// SessionByID is the public counterpart of the internal sessionByID helper
// already used by CreateSession, exposed to satisfy the Storage interface's
// SessionByID method.
func (s *Store) SessionByID(ctx context.Context, id theauth.ULID) (*theauth.Session, error) {
	return s.sessionByID(ctx, id)
}

func (s *Store) RevokeSession(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ?`,
		timeUTC(time.Now()),
		ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID theauth.ULID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		timeUTC(time.Now()),
		ulidToBytes(userID),
	)
	return err
}

func (s *Store) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET auth_level = ? WHERE id = ?`,
		level,
		ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET active_organization_id = ? WHERE id = ?`,
		ulidPtrToBytes(orgID),
		ulidToBytes(sessionID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

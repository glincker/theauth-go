package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go"
)

// CreateMagicLink stores a single-use magic link.
func (s *Store) CreateMagicLink(ctx context.Context, ml theauth.MagicLink) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_magic_links (id, email, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`),
		idStr(ml.ID), ml.Email, ml.TokenHash, toMicro(ml.ExpiresAt), toMicro(orNow(ml.CreatedAt)))
	return wrap("create magic link", err)
}

// ConsumeMagicLink atomically marks an unused, unexpired link used and returns it.
func (s *Store) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*theauth.MagicLink, error) {
	now := time.Now()
	var (
		id, email        string
		hash             []byte
		expires, created int64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_magic_links SET used_at = ?
WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
RETURNING id, email, token_hash, expires_at, created_at`),
		toMicro(now), tokenHash, toMicro(now),
	).Scan(&id, &email, &hash, &expires, &created)
	if err != nil {
		return nil, notFoundOr("consume magic link", err)
	}
	uid, err := parseID(id)
	if err != nil {
		return nil, wrap("consume magic link", err)
	}
	used := now.UTC()
	return &theauth.MagicLink{
		ID: uid, Email: email, TokenHash: hash,
		ExpiresAt: fromMicro(expires), UsedAt: &used, CreatedAt: fromMicro(created),
	}, nil
}

// SetUserPassword upserts the user's PHC hash and returns ErrStorageNotFound for an unknown user.
func (s *Store) SetUserPassword(ctx context.Context, userID theauth.ULID, passwordHash string) error {
	res, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_user_passwords (user_id, password_hash)
SELECT id, ? FROM theauth_users WHERE id = ?
ON CONFLICT (user_id) DO UPDATE SET password_hash = excluded.password_hash`),
		passwordHash, idStr(userID))
	if err != nil {
		return wrap("set user password", err)
	}
	return requireRows("set user password", res)
}

// UserByEmailWithPassword returns the user and their hash, empty when no password is set.
func (s *Store) UserByEmailWithPassword(ctx context.Context, email string) (*theauth.User, string, error) {
	u, err := s.UserByEmail(ctx, email)
	if err != nil {
		return nil, "", err
	}
	hash, err := s.UserPasswordHashByID(ctx, u.ID)
	if err != nil {
		return nil, "", err
	}
	return u, hash, nil
}

// UserPasswordHashByID returns the stored hash, or "" when the user has none.
func (s *Store) UserPasswordHashByID(ctx context.Context, userID theauth.ULID) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		s.q(`SELECT password_hash FROM theauth_user_passwords WHERE user_id = ?`), idStr(userID)).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, wrap("password hash by id", err)
}

// MovePasswordHash moves the hash from secondaryID to primaryID, overwriting any existing one.
func (s *Store) MovePasswordHash(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	if primaryID == secondaryID {
		return nil
	}
	return s.inTx(ctx, "move password hash", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_user_passwords (user_id, password_hash)
SELECT ?, password_hash FROM theauth_user_passwords WHERE user_id = ?
ON CONFLICT (user_id) DO UPDATE SET password_hash = excluded.password_hash`),
			idStr(primaryID), idStr(secondaryID))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx,
			s.q(`DELETE FROM theauth_user_passwords WHERE user_id = ?`), idStr(secondaryID))
		return err
	})
}

// CreatePasswordResetToken stores a single-use reset token.
func (s *Store) CreatePasswordResetToken(ctx context.Context, t theauth.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`),
		idStr(t.ID), idStr(t.UserID), t.TokenHash, toMicro(t.ExpiresAt), toMicro(orNow(t.CreatedAt)))
	return wrap("create password reset token", err)
}

// ConsumePasswordResetToken atomically marks an unused, unexpired token used and returns it.
func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*theauth.PasswordResetToken, error) {
	now := time.Now()
	var (
		id, userID       string
		hash             []byte
		expires, created int64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_password_reset_tokens SET used_at = ?
WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
RETURNING id, user_id, token_hash, expires_at, created_at`),
		toMicro(now), tokenHash, toMicro(now),
	).Scan(&id, &userID, &hash, &expires, &created)
	if err != nil {
		return nil, notFoundOr("consume password reset token", err)
	}
	tid, err := parseID(id)
	if err != nil {
		return nil, wrap("consume password reset token", err)
	}
	uid, err := parseID(userID)
	if err != nil {
		return nil, wrap("consume password reset token", err)
	}
	used := now.UTC()
	return &theauth.PasswordResetToken{
		ID: tid, UserID: uid, TokenHash: hash,
		ExpiresAt: fromMicro(expires), UsedAt: &used, CreatedAt: fromMicro(created),
	}, nil
}

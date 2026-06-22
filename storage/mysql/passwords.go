package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- Magic links ----------

func (s *Store) CreateMagicLink(ctx context.Context, ml theauth.MagicLink) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO magic_links (id, email, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`,
		ulidToBytes(ml.ID),
		strings.ToLower(ml.Email),
		ml.TokenHash,
		timeUTC(ml.ExpiresAt),
		timeUTC(ml.CreatedAt),
	)
	return err
}

func (s *Store) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*theauth.MagicLink, error) {
	// MySQL has no DELETE...RETURNING. Use SELECT FOR UPDATE then UPDATE,
	// then return the data. Wrapped in a transaction for atomicity.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		idB                []byte
		email              string
		hash               []byte
		expiresAt, created time.Time
		usedAt             sql.NullTime
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, email, token_hash, expires_at, used_at, created_at
		 FROM magic_links WHERE token_hash = ? AND used_at IS NULL
		 FOR UPDATE`,
		tokenHash,
	).Scan(&idB, &email, &hash, &expiresAt, &usedAt, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := timeUTC(time.Now())
	if _, err := tx.ExecContext(ctx,
		`UPDATE magic_links SET used_at = ? WHERE token_hash = ?`,
		now, tokenHash,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	ml := theauth.MagicLink{
		ID:        bytesToULID(idB),
		Email:     email,
		TokenHash: hash,
		ExpiresAt: expiresAt.UTC(),
		UsedAt:    &now,
		CreatedAt: created.UTC(),
	}
	return &ml, nil
}

// ---------- Password credentials ----------

func (s *Store) SetUserPassword(ctx context.Context, userID theauth.ULID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO user_passwords (user_id, password_hash) VALUES (?, ?)
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)`,
		ulidToBytes(userID), passwordHash,
	)
	return err
}

func (s *Store) UserByEmailWithPassword(ctx context.Context, email string) (*theauth.User, string, error) {
	u, err := s.UserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		return nil, "", err
	}
	ph, err := s.UserPasswordHashByID(ctx, u.ID)
	if err != nil {
		return nil, "", err
	}
	return u, ph, nil
}

func (s *Store) UserPasswordHashByID(ctx context.Context, userID theauth.ULID) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM user_passwords WHERE user_id = ?`,
		ulidToBytes(userID),
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (s *Store) MovePasswordHash(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var hash string
	err = tx.QueryRowContext(ctx,
		`SELECT password_hash FROM user_passwords WHERE user_id = ?`,
		ulidToBytes(secondaryID),
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no-op
	}
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO user_passwords (user_id, password_hash) VALUES (?, ?)
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)`,
		ulidToBytes(primaryID), hash,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM user_passwords WHERE user_id = ?`,
		ulidToBytes(secondaryID),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------- Password reset tokens ----------

func (s *Store) CreatePasswordResetToken(ctx context.Context, t theauth.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`,
		ulidToBytes(t.ID),
		ulidToBytes(t.UserID),
		t.TokenHash,
		timeUTC(t.ExpiresAt),
		timeUTC(t.CreatedAt),
	)
	return err
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*theauth.PasswordResetToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		idB, userIDB       []byte
		hash               []byte
		expiresAt, created time.Time
		usedAt             sql.NullTime
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		 FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL
		 FOR UPDATE`,
		tokenHash,
	).Scan(&idB, &userIDB, &hash, &expiresAt, &usedAt, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := timeUTC(time.Now())
	if _, err := tx.ExecContext(ctx,
		`UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?`,
		now, tokenHash,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	rt := theauth.PasswordResetToken{
		ID:        bytesToULID(idB),
		UserID:    bytesToULID(userIDB),
		TokenHash: hash,
		ExpiresAt: expiresAt.UTC(),
		UsedAt:    &now,
		CreatedAt: created.UTC(),
	}
	return &rt, nil
}

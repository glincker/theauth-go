package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
)

// UpsertPendingTOTPSecret writes an unconfirmed secret and leaves a confirmed one untouched.
func (s *Store) UpsertPendingTOTPSecret(ctx context.Context, sec theauth.TOTPSecret) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_totp_secrets (user_id, secret_enc, confirmed_at, created_at, updated_at)
VALUES (?, ?, NULL, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET secret_enc = excluded.secret_enc, updated_at = excluded.updated_at
WHERE theauth_totp_secrets.confirmed_at IS NULL`),
		idStr(sec.UserID), sec.SecretEnc, toMicro(orNow(sec.CreatedAt)), toMicro(now))
	return wrap("upsert pending totp secret", err)
}

// ConfirmTOTPSecret confirms the user's pending secret, else ErrStorageNotFound.
func (s *Store) ConfirmTOTPSecret(ctx context.Context, userID theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_totp_secrets SET confirmed_at = ?, updated_at = ?
WHERE user_id = ? AND confirmed_at IS NULL`),
		toMicro(at), toMicro(time.Now()), idStr(userID))
	if err != nil {
		return wrap("confirm totp secret", err)
	}
	return requireRows("confirm totp secret", res)
}

// TOTPSecretByUserID returns the user's secret row.
func (s *Store) TOTPSecretByUserID(ctx context.Context, userID theauth.ULID) (*theauth.TOTPSecret, error) {
	var (
		id               string
		enc              []byte
		confirmed        sql.NullInt64
		created, updated int64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
SELECT user_id, secret_enc, confirmed_at, created_at, updated_at
FROM theauth_totp_secrets WHERE user_id = ?`), idStr(userID)).Scan(&id, &enc, &confirmed, &created, &updated)
	if err != nil {
		return nil, notFoundOr("totp secret by user id", err)
	}
	uid, err := parseID(id)
	if err != nil {
		return nil, wrap("totp secret by user id", err)
	}
	return &theauth.TOTPSecret{
		UserID: uid, SecretEnc: enc, ConfirmedAt: fromNullMicro(confirmed),
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}, nil
}

// DeleteTOTPSecret removes the user's secret and recovery codes.
func (s *Store) DeleteTOTPSecret(ctx context.Context, userID theauth.ULID) error {
	return s.inTx(ctx, "delete totp secret", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			s.q(`DELETE FROM theauth_totp_recovery_codes WHERE user_id = ?`), idStr(userID)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q(`DELETE FROM theauth_totp_secrets WHERE user_id = ?`), idStr(userID))
		return err
	})
}

// MoveTOTPSecret moves secondaryID's secret to primaryID, or drops it when primaryID already has one.
func (s *Store) MoveTOTPSecret(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	if primaryID == secondaryID {
		return nil
	}
	return s.inTx(ctx, "move totp secret", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`
DELETE FROM theauth_totp_secrets WHERE user_id = ?
AND EXISTS (SELECT 1 FROM theauth_totp_secrets WHERE user_id = ?)`),
			idStr(secondaryID), idStr(primaryID)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			s.q(`UPDATE theauth_totp_secrets SET user_id = ? WHERE user_id = ?`), idStr(primaryID), idStr(secondaryID))
		return err
	})
}

// InsertRecoveryCodes stores a batch of recovery codes atomically.
func (s *Store) InsertRecoveryCodes(ctx context.Context, codes []theauth.RecoveryCode) error {
	if len(codes) == 0 {
		return nil
	}
	return s.inTx(ctx, "insert recovery codes", func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, s.q(`
INSERT INTO theauth_totp_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`))
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, c := range codes {
			if _, err := stmt.ExecContext(ctx, idStr(c.ID), idStr(c.UserID), c.CodeHash, toMicro(orNow(c.CreatedAt))); err != nil {
				return err
			}
		}
		return nil
	})
}

// ConsumeRecoveryCode marks the matching unused code used, else ErrStorageNotFound.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID theauth.ULID, code string, at time.Time) error {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT id, code_hash FROM theauth_totp_recovery_codes WHERE user_id = ? AND used_at IS NULL`), idStr(userID))
	if err != nil {
		return wrap("consume recovery code", err)
	}
	type candidate struct {
		id   string
		hash []byte
	}
	var cands []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			_ = rows.Close()
			return wrap("consume recovery code", err)
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return wrap("consume recovery code", err)
	}
	_ = rows.Close()

	for _, c := range cands {
		if !crypto.VerifyRecoveryCode(c.hash, code) {
			continue
		}
		res, err := s.db.ExecContext(ctx,
			s.q(`UPDATE theauth_totp_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`),
			toMicro(at), c.id)
		if err != nil {
			return wrap("consume recovery code", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
	}
	return notFoundOr("consume recovery code", sql.ErrNoRows)
}

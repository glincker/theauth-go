package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/storage"
)

// ---------- TOTP secrets ----------

func (s *Store) UpsertPendingTOTPSecret(ctx context.Context, sec theauth.TOTPSecret) error {
	created := sec.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	// Only overwrite an unconfirmed row; preserve a confirmed row.
	_, err := s.db.ExecContext(ctx, `
INSERT INTO totp_secrets (user_id, secret_enc, confirmed_at, created_at, updated_at)
VALUES (?, ?, NULL, ?, ?)
ON DUPLICATE KEY UPDATE
    secret_enc   = IF(confirmed_at IS NULL, VALUES(secret_enc), secret_enc),
    updated_at   = IF(confirmed_at IS NULL, VALUES(updated_at), updated_at)`,
		ulidToBytes(sec.UserID),
		sec.SecretEnc,
		timeUTC(created),
		timeUTC(time.Now()),
	)
	return err
}

func (s *Store) ConfirmTOTPSecret(ctx context.Context, userID theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE totp_secrets SET confirmed_at = ?, updated_at = ?
WHERE user_id = ? AND confirmed_at IS NULL`,
		timeUTC(at), timeUTC(time.Now()), ulidToBytes(userID),
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

func (s *Store) TOTPSecretByUserID(ctx context.Context, userID theauth.ULID) (*theauth.TOTPSecret, error) {
	var (
		userIDB     []byte
		secretEnc   []byte
		confirmedAt sql.NullTime
		createdAt   time.Time
		updatedAt   time.Time
	)
	err := s.db.QueryRowContext(ctx, `
SELECT user_id, secret_enc, confirmed_at, created_at, updated_at
FROM totp_secrets WHERE user_id = ?`,
		ulidToBytes(userID),
	).Scan(&userIDB, &secretEnc, &confirmedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sec := theauth.TOTPSecret{
		UserID:      bytesToULID(userIDB),
		SecretEnc:   secretEnc,
		ConfirmedAt: nullTimeToPtr(confirmedAt),
		CreatedAt:   createdAt.UTC(),
		UpdatedAt:   updatedAt.UTC(),
	}
	return &sec, nil
}

func (s *Store) DeleteTOTPSecret(ctx context.Context, userID theauth.ULID) error {
	// Delete recovery codes first (cascade would also handle it, but being
	// explicit keeps behaviour consistent with the postgres adapter).
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM totp_recovery_codes WHERE user_id = ?`,
		ulidToBytes(userID),
	); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM totp_secrets WHERE user_id = ?`,
		ulidToBytes(userID),
	)
	return err
}

func (s *Store) MoveTOTPSecret(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM totp_secrets WHERE user_id = ?`,
		ulidToBytes(primaryID),
	).Scan(&exists)
	primaryHas := !errors.Is(err, sql.ErrNoRows)

	if primaryHas {
		// Drop secondary; do not overwrite active primary factor.
		if _, delErr := tx.ExecContext(ctx,
			`DELETE FROM totp_secrets WHERE user_id = ?`, ulidToBytes(secondaryID),
		); delErr != nil {
			return delErr
		}
	} else {
		if _, upErr := tx.ExecContext(ctx,
			`UPDATE totp_secrets SET user_id = ? WHERE user_id = ?`,
			ulidToBytes(primaryID), ulidToBytes(secondaryID),
		); upErr != nil {
			return upErr
		}
	}
	return tx.Commit()
}

// ---------- Recovery codes ----------

func (s *Store) InsertRecoveryCodes(ctx context.Context, codes []theauth.RecoveryCode) error {
	for _, c := range codes {
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at)
VALUES (?, ?, ?, ?)`,
			ulidToBytes(c.ID),
			ulidToBytes(c.UserID),
			c.CodeHash,
			timeUTC(c.CreatedAt),
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID theauth.ULID, code string, at time.Time) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, code_hash FROM totp_recovery_codes
WHERE user_id = ? AND used_at IS NULL`,
		ulidToBytes(userID),
	)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	type candidate struct {
		idB      []byte
		codeHash []byte
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.idB, &c.codeHash); err != nil {
			return err
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, c := range candidates {
		if !crypto.VerifyRecoveryCode(c.codeHash, code) {
			continue
		}
		res, err := s.db.ExecContext(ctx,
			`UPDATE totp_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
			timeUTC(at), c.idB,
		)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue // lost race; try next
		}
		return nil
	}
	return storage.ErrNotFound
}

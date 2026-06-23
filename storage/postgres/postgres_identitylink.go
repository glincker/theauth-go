package postgres

// Identity-linking storage methods (v2.3). These run raw SQL via
// pgxpool.Pool rather than going through sqlc-generated code so that no
// schema regeneration is required. The queries are straightforward
// single-table statements with no complex joins or aggregates.

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// OAuthAccountsByUserID returns every oauth_accounts row linked to userID.
func (s *Store) OAuthAccountsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.OAuthAccount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, provider, provider_user_id,
		        access_token_enc, refresh_token_enc, expires_at, scope,
		        created_at, updated_at
		   FROM oauth_accounts WHERE user_id = $1`,
		ulidToPgUUID(userID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []theauth.OAuthAccount
	for rows.Next() {
		var (
			id, uid               pgtype.UUID
			provider, provUserID  string
			accessEnc, refreshEnc []byte
			expiresAt             pgtype.Timestamptz
			scope                 string
			createdAt, updatedAt  pgtype.Timestamptz
		)
		if err := rows.Scan(
			&id, &uid,
			&provider, &provUserID,
			&accessEnc, &refreshEnc,
			&expiresAt, &scope,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		a := theauth.OAuthAccount{
			ID:              pgUUIDToULID(id),
			UserID:          pgUUIDToULID(uid),
			Provider:        provider,
			ProviderUserID:  provUserID,
			AccessTokenEnc:  accessEnc,
			RefreshTokenEnc: refreshEnc,
			ExpiresAt:       tsToTimePtr(expiresAt),
			Scope:           scope,
			CreatedAt:       tsToTime(createdAt),
			UpdatedAt:       tsToTime(updatedAt),
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MoveOAuthAccount reassigns the row keyed by (provider, providerUserID) to
// newUserID.
func (s *Store) MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID theauth.ULID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE oauth_accounts SET user_id = $3, updated_at = now()
		   WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID, ulidToPgUUID(newUserID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteOAuthAccountByProvider removes the row for (userID, provider).
func (s *Store) DeleteOAuthAccountByProvider(ctx context.Context, userID theauth.ULID, provider string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2`,
		ulidToPgUUID(userID), provider,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// UserPasswordHashByID returns the stored Argon2id PHC string for the user,
// or "" when no password row exists.
func (s *Store) UserPasswordHashByID(ctx context.Context, userID theauth.ULID) (string, error) {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM user_passwords WHERE user_id = $1`,
		ulidToPgUUID(userID),
	).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return hash, nil
}

// MovePasswordHash copies the Argon2id hash from secondaryID to primaryID,
// overwriting any existing hash for primaryID, then clears secondaryID's row.
// A no-op when secondaryID has no password row.
func (s *Store) MovePasswordHash(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var hash string
	err = tx.QueryRow(ctx,
		`SELECT password_hash FROM user_passwords WHERE user_id = $1`,
		ulidToPgUUID(secondaryID),
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // no-op: secondary has no password
	}
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO user_passwords (user_id, password_hash)
		      VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
		ulidToPgUUID(primaryID), hash,
	)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx,
		`DELETE FROM user_passwords WHERE user_id = $1`,
		ulidToPgUUID(secondaryID),
	)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// MoveWebAuthnCredentials reassigns every WebAuthn credential row from
// secondaryID to primaryID.
func (s *Store) MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE webauthn_credentials SET user_id = $1 WHERE user_id = $2`,
		ulidToPgUUID(primaryID), ulidToPgUUID(secondaryID),
	)
	return err
}

// MoveTOTPSecret reassigns the TOTP secret from secondaryID to primaryID.
// If primaryID already has a confirmed TOTP secret the secondary row is
// deleted without overwriting the active primary factor.
func (s *Store) MoveTOTPSecret(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE user_id = $1)`,
		ulidToPgUUID(primaryID),
	).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		_, err = tx.Exec(ctx,
			`UPDATE totp_secrets SET user_id = $1 WHERE user_id = $2`,
			ulidToPgUUID(primaryID), ulidToPgUUID(secondaryID),
		)
	} else {
		_, err = tx.Exec(ctx,
			`DELETE FROM totp_secrets WHERE user_id = $1`,
			ulidToPgUUID(secondaryID),
		)
	}
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

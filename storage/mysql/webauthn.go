package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- OAuth accounts ----------

func (s *Store) UpsertOAuthAccount(ctx context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	// Upsert keyed on (provider, provider_user_id). On conflict update tokens.
	_, err := s.db.ExecContext(ctx, `
INSERT INTO oauth_accounts
    (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc,
     expires_at, scope, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    access_token_enc  = VALUES(access_token_enc),
    refresh_token_enc = VALUES(refresh_token_enc),
    expires_at        = VALUES(expires_at),
    scope             = VALUES(scope),
    updated_at        = VALUES(updated_at)`,
		ulidToBytes(a.ID),
		ulidToBytes(a.UserID),
		a.Provider,
		a.ProviderUserID,
		a.AccessTokenEnc,
		nullBytesToSlice(a.RefreshTokenEnc),
		timePtrToNull(a.ExpiresAt),
		a.Scope,
		timeUTC(a.CreatedAt),
		timeUTC(a.UpdatedAt),
	)
	if err != nil {
		return theauth.OAuthAccount{}, err
	}
	got, err := s.OAuthAccountByProviderUserID(ctx, a.Provider, a.ProviderUserID)
	if err != nil {
		return theauth.OAuthAccount{}, err
	}
	return *got, nil
}

func (s *Store) OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc,
       expires_at, scope, created_at, updated_at
FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?`,
		provider, providerUserID,
	)
	a, err := scanOAuthAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) OAuthAccountsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.OAuthAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc,
       expires_at, scope, created_at, updated_at
FROM oauth_accounts WHERE user_id = ?`,
		ulidToBytes(userID),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.OAuthAccount
	for rows.Next() {
		a, err := scanOAuthAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oauth_accounts SET user_id = ?, updated_at = ?
		 WHERE provider = ? AND provider_user_id = ?`,
		ulidToBytes(newUserID), timeUTC(time.Now()), provider, providerUserID,
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

func (s *Store) DeleteOAuthAccountByProvider(ctx context.Context, userID theauth.ULID, provider string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_accounts WHERE user_id = ? AND provider = ?`,
		ulidToBytes(userID), provider,
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

func scanOAuthAccount(row interface{ Scan(...interface{}) error }) (theauth.OAuthAccount, error) {
	var (
		idB, userIDB         []byte
		provider, provUserID string
		accessEnc, refEnc    []byte
		expiresAt            sql.NullTime
		scope                string
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(
		&idB, &userIDB,
		&provider, &provUserID,
		&accessEnc, &refEnc,
		&expiresAt, &scope,
		&createdAt, &updatedAt,
	); err != nil {
		return theauth.OAuthAccount{}, err
	}
	return theauth.OAuthAccount{
		ID:              bytesToULID(idB),
		UserID:          bytesToULID(userIDB),
		Provider:        provider,
		ProviderUserID:  provUserID,
		AccessTokenEnc:  accessEnc,
		RefreshTokenEnc: refEnc,
		ExpiresAt:       nullTimeToPtr(expiresAt),
		Scope:           scope,
		CreatedAt:       createdAt.UTC(),
		UpdatedAt:       updatedAt.UTC(),
	}, nil
}

// ---------- WebAuthn credentials ----------

func (s *Store) InsertWebAuthnCredential(ctx context.Context, c theauth.WebAuthnCredential) (theauth.WebAuthnCredential, error) {
	transports := c.Transports
	if transports == nil {
		transports = []string{}
	}
	transportsJSON, err := json.Marshal(transports)
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO webauthn_credentials
    (id, user_id, credential_id, public_key, sign_count, transports, aaguid, name, created_at, last_used_at, backup_eligible, backup_state)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(c.ID),
		ulidToBytes(c.UserID),
		c.CredentialID,
		c.PublicKey,
		int64(c.SignCount),
		transportsJSON,
		c.AAGUID,
		c.Name,
		timeUTC(c.CreatedAt),
		timePtrToNull(c.LastUsedAt),
		boolPtrToNull(c.BackupEligible),
		boolPtrToNull(c.BackupState),
	)
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	got, err := s.WebAuthnCredentialByCredentialID(ctx, c.CredentialID)
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	return *got, nil
}

func (s *Store) WebAuthnCredentialsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, credential_id, public_key, sign_count, transports, aaguid, name, created_at, last_used_at, backup_eligible, backup_state
FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC`,
		ulidToBytes(userID),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*theauth.WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, user_id, credential_id, public_key, sign_count, transports, aaguid, name, created_at, last_used_at, backup_eligible, backup_state
FROM webauthn_credentials WHERE credential_id = ?`,
		credentialID,
	)
	c, err := scanWebAuthnCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE webauthn_credentials
SET sign_count = ?, last_used_at = ?
WHERE credential_id = ? AND sign_count < ?`,
		int64(newCount), timeUTC(usedAt), credentialID, int64(newCount),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return nil
	}
	// Distinguish "missing" from "replay".
	var exists int
	if scanErr := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM webauthn_credentials WHERE credential_id = ?`, credentialID,
	).Scan(&exists); errors.Is(scanErr, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	return theauth.ErrReplayDetected
}

// UpdateWebAuthnBackupFlags records the BE / BS flags for a credential that
// had none stored (trust-on-first-use reconciliation for legacy synced
// passkeys). A missing credential is a no-op returning nil, mirroring the
// Postgres adapter: the caller treats reconciliation as best-effort.
func (s *Store) UpdateWebAuthnBackupFlags(ctx context.Context, credentialID []byte, backupEligible, backupState bool) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE webauthn_credentials
SET backup_eligible = ?, backup_state = ?
WHERE credential_id = ?`,
		backupEligible, backupState, credentialID,
	)
	return err
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id theauth.ULID, userID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`,
		ulidToBytes(id), ulidToBytes(userID),
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

func (s *Store) MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET user_id = ? WHERE user_id = ?`,
		ulidToBytes(primaryID), ulidToBytes(secondaryID),
	)
	return err
}

func scanWebAuthnCredential(row interface{ Scan(...interface{}) error }) (theauth.WebAuthnCredential, error) {
	var (
		idB, userIDB, credIDB []byte
		pubKey, aaguid        []byte
		signCount             int64
		transportsJSON        []byte
		name                  string
		createdAt             time.Time
		lastUsedAt            sql.NullTime
		backupEligible        sql.NullBool
		backupState           sql.NullBool
	)
	if err := row.Scan(
		&idB, &userIDB, &credIDB,
		&pubKey, &signCount, &transportsJSON,
		&aaguid, &name, &createdAt, &lastUsedAt,
		&backupEligible, &backupState,
	); err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	var transports []string
	if len(transportsJSON) > 0 {
		_ = json.Unmarshal(transportsJSON, &transports)
	}
	if transports == nil {
		transports = []string{}
	}
	sc := uint32(0)
	if signCount >= 0 {
		sc = uint32(signCount)
	}
	return theauth.WebAuthnCredential{
		ID:             bytesToULID(idB),
		UserID:         bytesToULID(userIDB),
		CredentialID:   credIDB,
		PublicKey:      pubKey,
		SignCount:      sc,
		Transports:     transports,
		AAGUID:         aaguid,
		Name:           name,
		CreatedAt:      createdAt.UTC(),
		LastUsedAt:     nullTimeToPtr(lastUsedAt),
		BackupEligible: nullBoolToPtr(backupEligible),
		BackupState:    nullBoolToPtr(backupState),
	}, nil
}

// boolPtrToNull converts a *bool into a sql.NullBool for a nullable column
// (nil -> SQL NULL).
func boolPtrToNull(p *bool) sql.NullBool {
	if p == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *p, Valid: true}
}

// nullBoolToPtr is the inverse: an invalid (NULL) value maps to nil.
func nullBoolToPtr(nb sql.NullBool) *bool {
	if !nb.Valid {
		return nil
	}
	v := nb.Bool
	return &v
}

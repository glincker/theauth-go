package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

const webauthnCols = `id, user_id, credential_id, public_key, sign_count, transports, aaguid, name,
	created_at, last_used_at, backup_eligible, backup_state`

func nullBool(p *bool) sql.NullBool {
	if p == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *p, Valid: true}
}

func boolPtr(n sql.NullBool) *bool {
	if !n.Valid {
		return nil
	}
	v := n.Bool
	return &v
}

func scanWebAuthn(r scanner) (theauth.WebAuthnCredential, error) {
	var (
		id, userID, transports, name string
		credID, pub, aaguid          []byte
		signCount, created           int64
		lastUsed                     sql.NullInt64
		be, bs                       sql.NullBool
	)
	if err := r.Scan(&id, &userID, &credID, &pub, &signCount, &transports, &aaguid, &name,
		&created, &lastUsed, &be, &bs); err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	cid, err := parseID(id)
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	ts := []string{}
	if err := json.Unmarshal([]byte(transports), &ts); err != nil {
		return theauth.WebAuthnCredential{}, fmt.Errorf("decode transports: %w", err)
	}
	return theauth.WebAuthnCredential{
		ID: cid, UserID: uid, CredentialID: credID, PublicKey: pub,
		SignCount: uint32(signCount), Transports: ts, AAGUID: aaguid, Name: name,
		CreatedAt: fromMicro(created), LastUsedAt: fromNullMicro(lastUsed),
		BackupEligible: boolPtr(be), BackupState: boolPtr(bs),
	}, nil
}

// InsertWebAuthnCredential stores a credential and returns the stored row.
func (s *Store) InsertWebAuthnCredential(ctx context.Context, c theauth.WebAuthnCredential) (theauth.WebAuthnCredential, error) {
	ts := c.Transports
	if ts == nil {
		ts = []string{}
	}
	tsJSON, err := json.Marshal(ts)
	if err != nil {
		return theauth.WebAuthnCredential{}, wrap("insert webauthn credential", err)
	}
	row := s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_webauthn_credentials (`+webauthnCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING `+webauthnCols),
		idStr(c.ID), idStr(c.UserID), c.CredentialID, c.PublicKey, int64(c.SignCount), string(tsJSON),
		nonNilBytes(c.AAGUID), c.Name, toMicro(orNow(c.CreatedAt)), toNullMicro(c.LastUsedAt),
		nullBool(c.BackupEligible), nullBool(c.BackupState))
	out, err := scanWebAuthn(row)
	if err != nil {
		return theauth.WebAuthnCredential{}, wrap("insert webauthn credential", err)
	}
	return out, nil
}

// WebAuthnCredentialsByUserID lists a user's credentials oldest first.
func (s *Store) WebAuthnCredentialsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT `+webauthnCols+` FROM theauth_webauthn_credentials WHERE user_id = ? ORDER BY created_at, id`),
		idStr(userID))
	if err != nil {
		return nil, wrap("webauthn credentials by user id", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.WebAuthnCredential{}
	for rows.Next() {
		c, err := scanWebAuthn(rows)
		if err != nil {
			return nil, wrap("webauthn credentials by user id", err)
		}
		out = append(out, c)
	}
	return out, wrap("webauthn credentials by user id", rows.Err())
}

// WebAuthnCredentialByCredentialID looks up a credential by its authenticator ID.
func (s *Store) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*theauth.WebAuthnCredential, error) {
	c, err := scanWebAuthn(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+webauthnCols+` FROM theauth_webauthn_credentials WHERE credential_id = ?`), credentialID))
	if err != nil {
		return nil, notFoundOr("webauthn credential by credential id", err)
	}
	return &c, nil
}

// UpdateWebAuthnSignCount writes a strictly greater count, else ErrReplayDetected or ErrStorageNotFound.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_webauthn_credentials SET sign_count = ?, last_used_at = ?
WHERE credential_id = ? AND sign_count < ?`),
		int64(newCount), toMicro(usedAt), credentialID, int64(newCount))
	if err != nil {
		return wrap("update webauthn sign count", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx,
		s.q(`SELECT 1 FROM theauth_webauthn_credentials WHERE credential_id = ?`), credentialID).Scan(&one)
	if err != nil {
		return notFoundOr("update webauthn sign count", err)
	}
	return theauth.ErrReplayDetected
}

// UpdateWebAuthnBackupFlags records BE and BS flags, and is a no-op for a missing credential.
func (s *Store) UpdateWebAuthnBackupFlags(ctx context.Context, credentialID []byte, backupEligible, backupState bool) error {
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_webauthn_credentials SET backup_eligible = ?, backup_state = ? WHERE credential_id = ?`),
		backupEligible, backupState, credentialID)
	return wrap("update webauthn backup flags", err)
}

// DeleteWebAuthnCredential removes a credential owned by userID.
func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id theauth.ULID, userID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		s.q(`DELETE FROM theauth_webauthn_credentials WHERE id = ? AND user_id = ?`), idStr(id), idStr(userID))
	if err != nil {
		return wrap("delete webauthn credential", err)
	}
	return requireRows("delete webauthn credential", res)
}

// MoveWebAuthnCredentials reassigns every credential of secondaryID to primaryID.
func (s *Store) MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	_, err := s.db.ExecContext(ctx,
		s.q(`UPDATE theauth_webauthn_credentials SET user_id = ? WHERE user_id = ?`), idStr(primaryID), idStr(secondaryID))
	return wrap("move webauthn credentials", err)
}

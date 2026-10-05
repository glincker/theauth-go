package sqlite

import (
	"context"
	"database/sql"

	"github.com/glincker/theauth-go"
)

var (
	_ theauth.WebAuthnRenameStorage = (*Store)(nil)
	_ theauth.RecoveryCodeStorage   = (*Store)(nil)
)

// RenameWebAuthnCredential sets a passkey's display name when it belongs to userID.
func (s *Store) RenameWebAuthnCredential(ctx context.Context, id, userID theauth.ULID, name string) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`), name, idStr(id), idStr(userID))
	if err != nil {
		return wrap("rename webauthn credential", err)
	}
	return requireRows("rename webauthn credential", res)
}

// CountUnusedRecoveryCodes returns how many unused recovery codes userID holds.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID theauth.ULID) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM theauth_totp_recovery_codes WHERE user_id = ? AND used_at IS NULL`), idStr(userID)).Scan(&n)
	if err != nil {
		return 0, wrap("count unused recovery codes", err)
	}
	return n, nil
}

// ReplaceRecoveryCodes atomically swaps every recovery code of userID for codes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID theauth.ULID, codes []theauth.RecoveryCode) error {
	return s.inTx(ctx, "replace recovery codes", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			s.q(`DELETE FROM theauth_totp_recovery_codes WHERE user_id = ?`), idStr(userID)); err != nil {
			return err
		}
		for _, c := range codes {
			if _, err := tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_totp_recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES (?, ?, ?, ?, ?)`),
				idStr(c.ID), idStr(userID), c.CodeHash, toNullMicro(c.UsedAt), toMicro(orNow(c.CreatedAt))); err != nil {
				return err
			}
		}
		return nil
	})
}

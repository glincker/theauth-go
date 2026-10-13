package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var (
	_ theauth.AccountStateStorage  = (*Store)(nil)
	_ theauth.AccountDeleteStorage = (*Store)(nil)
	_ theauth.TrustedDeviceStorage = (*Store)(nil)
)

// AccountStateByUserID returns the user's lifecycle flags; a user without a row yields the zero state.
func (s *Store) AccountStateByUserID(ctx context.Context, userID theauth.ULID) (theauth.AccountState, error) {
	var must int
	var disabled sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT must_change_password, disabled_at FROM theauth_account_states WHERE user_id = ?`), idStr(userID)).
		Scan(&must, &disabled)
	if err == sql.ErrNoRows {
		return theauth.AccountState{}, nil
	}
	if err != nil {
		return theauth.AccountState{}, wrap("account state", err)
	}
	return theauth.AccountState{MustChangePassword: must != 0, DisabledAt: fromNullMicro(disabled)}, nil
}

func (s *Store) userExists(ctx context.Context, tx DBTX, userID theauth.ULID) error {
	var one int
	err := tx.QueryRowContext(ctx, s.q(`SELECT 1 FROM theauth_users WHERE id = ?`), idStr(userID)).Scan(&one)
	return notFoundOr("user exists", err)
}

// SetMustChangePassword sets or clears the forced password change flag.
func (s *Store) SetMustChangePassword(ctx context.Context, userID theauth.ULID, required bool) error {
	flag := 0
	if required {
		flag = 1
	}
	return s.inTx(ctx, "set must change password", func(tx DBTX) error {
		if err := s.userExists(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_account_states (user_id, must_change_password) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET must_change_password = excluded.must_change_password`), idStr(userID), flag)
		return err
	})
}

// SetUserDisabledAt disables the user at the given time, or re-enables it when at is nil.
func (s *Store) SetUserDisabledAt(ctx context.Context, userID theauth.ULID, at *time.Time) error {
	return s.inTx(ctx, "set user disabled", func(tx DBTX) error {
		if err := s.userExists(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_account_states (user_id, disabled_at) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET disabled_at = excluded.disabled_at`), idStr(userID), toNullMicro(at))
		return err
	})
}

// DeleteUserCascade removes the user and every row that belongs to it in one transaction.
func (s *Store) DeleteUserCascade(ctx context.Context, userID theauth.ULID) error {
	uid := idStr(userID)
	return s.inTx(ctx, "delete user cascade", func(tx DBTX) error {
		var email string
		err := tx.QueryRowContext(ctx, s.q(`SELECT email FROM theauth_users WHERE id = ?`), uid).Scan(&email)
		if err != nil {
			return notFoundOr("delete user", err)
		}
		// Explicit deletes keep this correct when foreign keys are off.
		stmts := []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM theauth_sessions WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_password_reset_tokens WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_magic_links WHERE email = ?`, []any{email}},
			{`DELETE FROM theauth_oauth_accounts WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_webauthn_credentials WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_totp_recovery_codes WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_totp_secrets WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_totp_last_steps WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_session_links WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_trusted_devices WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_account_states WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_user_passwords WHERE user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_api_tokens WHERE owner_id = ? OR delegated_by = ?`, []any{uid, uid}},
			{`UPDATE theauth_audit_events SET actor_user_id = NULL WHERE actor_user_id = ?`, []any{uid}},
			{`DELETE FROM theauth_users WHERE id = ?`, []any{uid}},
		}
		for _, st := range stmts {
			if _, err := tx.ExecContext(ctx, s.q(st.sql), st.args...); err != nil {
				return err
			}
		}
		return nil
	})
}

// InsertTrustedDevice stores a remember-this-device record.
func (s *Store) InsertTrustedDevice(ctx context.Context, d theauth.TrustedDevice) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_trusted_devices (id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(d.ID), idStr(d.UserID), d.TokenHash, d.Label, d.UserAgent, d.IP,
		toMicro(orNow(d.CreatedAt)), toMicro(orNow(d.LastUsedAt)), toMicro(d.ExpiresAt), toNullMicro(d.RevokedAt))
	return wrap("insert trusted device", err)
}

const trustedCols = `id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at`

func scanTrusted(r scanner) (theauth.TrustedDevice, error) {
	var (
		id, uid, label, ua, ip string
		hash                   []byte
		created, used, expires int64
		revoked                sql.NullInt64
	)
	if err := r.Scan(&id, &uid, &hash, &label, &ua, &ip, &created, &used, &expires, &revoked); err != nil {
		return theauth.TrustedDevice{}, err
	}
	did, err := parseID(id)
	if err != nil {
		return theauth.TrustedDevice{}, err
	}
	duid, err := parseID(uid)
	if err != nil {
		return theauth.TrustedDevice{}, err
	}
	return theauth.TrustedDevice{
		ID: did, UserID: duid, TokenHash: hash, Label: label, UserAgent: ua, IP: ip,
		CreatedAt: fromMicro(created), LastUsedAt: fromMicro(used), ExpiresAt: fromMicro(expires),
		RevokedAt: fromNullMicro(revoked),
	}, nil
}

// TrustedDeviceByTokenHash returns the record for userID and hash, revoked or expired rows included.
func (s *Store) TrustedDeviceByTokenHash(ctx context.Context, userID theauth.ULID, hash []byte) (*theauth.TrustedDevice, error) {
	d, err := scanTrusted(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+trustedCols+` FROM theauth_trusted_devices WHERE user_id = ? AND token_hash = ?`), idStr(userID), hash))
	if err != nil {
		return nil, notFoundOr("trusted device by hash", err)
	}
	return &d, nil
}

// ListTrustedDevices returns the user's unrevoked, unexpired devices, newest first.
func (s *Store) ListTrustedDevices(ctx context.Context, userID theauth.ULID) ([]theauth.TrustedDevice, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+trustedCols+` FROM theauth_trusted_devices
WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC, id DESC`),
		idStr(userID), toMicro(time.Now()))
	if err != nil {
		return nil, wrap("list trusted devices", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.TrustedDevice
	for rows.Next() {
		d, err := scanTrusted(rows)
		if err != nil {
			return nil, wrap("scan trusted device", err)
		}
		out = append(out, d)
	}
	return out, wrap("list trusted devices", rows.Err())
}

// TouchTrustedDevice sets LastUsedAt.
func (s *Store) TouchTrustedDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE theauth_trusted_devices SET last_used_at = ? WHERE id = ?`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("touch trusted device", err)
	}
	return requireRows("touch trusted device", res)
}

// RevokeTrustedDevice revokes one live device owned by userID.
func (s *Store) RevokeTrustedDevice(ctx context.Context, userID, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_trusted_devices SET revoked_at = ?
WHERE id = ? AND user_id = ? AND revoked_at IS NULL`), toMicro(time.Now()), idStr(id), idStr(userID))
	if err != nil {
		return wrap("revoke trusted device", err)
	}
	return requireRows("revoke trusted device", res)
}

// RevokeUserTrustedDevices revokes every live device of userID and returns how many it revoked.
func (s *Store) RevokeUserTrustedDevices(ctx context.Context, userID theauth.ULID) (int, error) {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_trusted_devices SET revoked_at = ?
WHERE user_id = ? AND revoked_at IS NULL`), toMicro(time.Now()), idStr(userID))
	if err != nil {
		return 0, wrap("revoke user trusted devices", err)
	}
	n, err := res.RowsAffected()
	return int(n), wrap("revoke user trusted devices", err)
}

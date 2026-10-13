package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

var (
	_ theauth.AccountStateStorage  = (*Store)(nil)
	_ theauth.AccountDeleteStorage = (*Store)(nil)
	_ theauth.TrustedDeviceStorage = (*Store)(nil)
)

// AccountStateByUserID returns the user's lifecycle flags; a user without a row yields the zero state.
func (s *Store) AccountStateByUserID(ctx context.Context, userID theauth.ULID) (theauth.AccountState, error) {
	var must bool
	var disabled sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT must_change_password, disabled_at FROM account_states WHERE user_id = ?`,
		ulidToBytes(userID)).Scan(&must, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return theauth.AccountState{}, nil
	}
	if err != nil {
		return theauth.AccountState{}, fmt.Errorf("mysql: account state: %w", err)
	}
	return theauth.AccountState{MustChangePassword: must, DisabledAt: nullTimeToPtr(disabled)}, nil
}

func (s *Store) userRowExists(ctx context.Context, userID theauth.ULID) error {
	ok, err := s.rowExists(ctx, "users", userID)
	if err != nil {
		return fmt.Errorf("mysql: user exists: %w", err)
	}
	if !ok {
		return storage.ErrNotFound
	}
	return nil
}

// SetMustChangePassword sets or clears the forced password change flag.
func (s *Store) SetMustChangePassword(ctx context.Context, userID theauth.ULID, required bool) error {
	if err := s.userRowExists(ctx, userID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_states (user_id, must_change_password) VALUES (?, ?)
ON DUPLICATE KEY UPDATE must_change_password = VALUES(must_change_password)`, ulidToBytes(userID), required)
	if err != nil {
		return fmt.Errorf("mysql: set must change password: %w", err)
	}
	return nil
}

// SetUserDisabledAt disables the user at the given time, or re-enables it when at is nil.
func (s *Store) SetUserDisabledAt(ctx context.Context, userID theauth.ULID, at *time.Time) error {
	if err := s.userRowExists(ctx, userID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_states (user_id, disabled_at) VALUES (?, ?)
ON DUPLICATE KEY UPDATE disabled_at = VALUES(disabled_at)`, ulidToBytes(userID), timePtrToNull(at))
	if err != nil {
		return fmt.Errorf("mysql: set user disabled: %w", err)
	}
	return nil
}

// DeleteUserCascade removes the user and every row that belongs to it in one
// transaction. Foreign keys cascade everything except API tokens and magic
// links, which carry no user foreign key.
func (s *Store) DeleteUserCascade(ctx context.Context, userID theauth.ULID) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql: delete user cascade: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	uid := ulidToBytes(userID)
	var email string
	if qerr := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, uid).Scan(&email); qerr != nil {
		if errors.Is(qerr, sql.ErrNoRows) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("mysql: delete user cascade: %w", qerr)
	}
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM api_tokens WHERE owner_id = ? OR delegated_by = ?`, []any{uid, uid}},
		{`DELETE FROM magic_links WHERE email = ?`, []any{email}},
		{`DELETE FROM users WHERE id = ?`, []any{uid}},
	}
	for _, st := range stmts {
		if _, err := tx.ExecContext(ctx, st.sql, st.args...); err != nil {
			return fmt.Errorf("mysql: delete user cascade: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mysql: delete user cascade: commit: %w", err)
	}
	return nil
}

const trustedCols = `id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at`

func scanTrusted(r rowScanner) (theauth.TrustedDevice, error) {
	var (
		id, uid                []byte
		hash                   []byte
		label, ua, ip          string
		created, used, expires time.Time
		revoked                sql.NullTime
	)
	if err := r.Scan(&id, &uid, &hash, &label, &ua, &ip, &created, &used, &expires, &revoked); err != nil {
		return theauth.TrustedDevice{}, err
	}
	return theauth.TrustedDevice{
		ID: bytesToULID(id), UserID: bytesToULID(uid), TokenHash: hash, Label: label, UserAgent: ua, IP: ip,
		CreatedAt: created.UTC(), LastUsedAt: used.UTC(), ExpiresAt: expires.UTC(), RevokedAt: nullTimeToPtr(revoked),
	}, nil
}

// InsertTrustedDevice stores a remember-this-device record.
func (s *Store) InsertTrustedDevice(ctx context.Context, d theauth.TrustedDevice) error {
	created, used := d.CreatedAt, d.LastUsedAt
	if created.IsZero() {
		created = time.Now()
	}
	if used.IsZero() {
		used = created
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO trusted_devices (id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(d.ID), ulidToBytes(d.UserID), d.TokenHash, d.Label, d.UserAgent, d.IP,
		timeUTC(created), timeUTC(used), timeUTC(d.ExpiresAt), timePtrToNull(d.RevokedAt))
	if err != nil {
		return fmt.Errorf("mysql: insert trusted device: %w", err)
	}
	return nil
}

// TrustedDeviceByTokenHash returns the record for userID and hash, revoked or expired rows included.
func (s *Store) TrustedDeviceByTokenHash(ctx context.Context, userID theauth.ULID, hash []byte) (*theauth.TrustedDevice, error) {
	d, err := scanTrusted(s.db.QueryRowContext(ctx,
		`SELECT `+trustedCols+` FROM trusted_devices WHERE user_id = ? AND token_hash = ?`, ulidToBytes(userID), hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: trusted device by hash: %w", err)
	}
	return &d, nil
}

// ListTrustedDevices returns the user's unrevoked, unexpired devices, newest first.
func (s *Store) ListTrustedDevices(ctx context.Context, userID theauth.ULID) ([]theauth.TrustedDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+trustedCols+` FROM trusted_devices
WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC, id DESC`,
		ulidToBytes(userID), timeUTC(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("mysql: list trusted devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.TrustedDevice
	for rows.Next() {
		d, err := scanTrusted(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: list trusted devices: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: list trusted devices: %w", err)
	}
	return out, nil
}

// TouchTrustedDevice sets LastUsedAt.
func (s *Store) TouchTrustedDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.execOnRow(ctx, "touch trusted device", "trusted_devices", id,
		`UPDATE trusted_devices SET last_used_at = ? WHERE id = ?`, timeUTC(at), ulidToBytes(id))
}

// RevokeTrustedDevice revokes one live device owned by userID.
func (s *Store) RevokeTrustedDevice(ctx context.Context, userID, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, `UPDATE trusted_devices SET revoked_at = ?
WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, timeUTC(time.Now()), ulidToBytes(id), ulidToBytes(userID))
	n, err := rowsCount("revoke trusted device", res, err)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("mysql: revoke trusted device: %w", storage.ErrNotFound)
	}
	return nil
}

// RevokeUserTrustedDevices revokes every live device of userID and returns how many it revoked.
func (s *Store) RevokeUserTrustedDevices(ctx context.Context, userID theauth.ULID) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE trusted_devices SET revoked_at = ?
WHERE user_id = ? AND revoked_at IS NULL`, timeUTC(time.Now()), ulidToBytes(userID))
	return rowsCount("revoke user trusted devices", res, err)
}

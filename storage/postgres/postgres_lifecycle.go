package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	_ theauth.AccountStateStorage  = (*Store)(nil)
	_ theauth.AccountDeleteStorage = (*Store)(nil)
	_ theauth.TrustedDeviceStorage = (*Store)(nil)
)

// AccountStateByUserID returns the user's lifecycle flags; a user without a row yields the zero state.
func (s *Store) AccountStateByUserID(ctx context.Context, userID theauth.ULID) (theauth.AccountState, error) {
	var must bool
	var disabled pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `SELECT must_change_password, disabled_at FROM account_states WHERE user_id = $1`,
		ulidToPgUUID(userID)).Scan(&must, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return theauth.AccountState{}, nil
	}
	if err != nil {
		return theauth.AccountState{}, fmt.Errorf("postgres: account state: %w", err)
	}
	return theauth.AccountState{MustChangePassword: must, DisabledAt: tsToTimePtr(disabled)}, nil
}

func (s *Store) userRowExists(ctx context.Context, userID theauth.ULID) error {
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM users WHERE id = $1`, ulidToPgUUID(userID)).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: user exists: %w", err)
	}
	return nil
}

// SetMustChangePassword sets or clears the forced password change flag.
func (s *Store) SetMustChangePassword(ctx context.Context, userID theauth.ULID, required bool) error {
	if err := s.userRowExists(ctx, userID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO account_states (user_id, must_change_password) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET must_change_password = EXCLUDED.must_change_password`,
		ulidToPgUUID(userID), required)
	if err != nil {
		return fmt.Errorf("postgres: set must change password: %w", err)
	}
	return nil
}

// SetUserDisabledAt disables the user at the given time, or re-enables it when at is nil.
func (s *Store) SetUserDisabledAt(ctx context.Context, userID theauth.ULID, at *time.Time) error {
	if err := s.userRowExists(ctx, userID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO account_states (user_id, disabled_at) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET disabled_at = EXCLUDED.disabled_at`,
		ulidToPgUUID(userID), timePtrToTs(at))
	if err != nil {
		return fmt.Errorf("postgres: set user disabled: %w", err)
	}
	return nil
}

// DeleteUserCascade removes the user and its rows in one transaction. Foreign keys cascade everything
// except API tokens and magic links, which have no user foreign key.
func (s *Store) DeleteUserCascade(ctx context.Context, userID theauth.ULID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: delete user cascade: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	uid := ulidToPgUUID(userID)
	var email string
	if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, uid).Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("postgres: delete user cascade: %w", err)
	}
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM api_tokens WHERE owner_id = $1 OR delegated_by = $1`, []any{uid}},
		{`DELETE FROM magic_links WHERE email = $1`, []any{email}},
		// Blank the free-text id columns; hashed pseudonyms stay so the audit chain still verifies.
		// Pre-chain rows (chain_seq NULL) are left alone.
		{`UPDATE audit_events SET subject_id = '' WHERE subject_id = $1 AND chain_seq IS NOT NULL`, []any{userID.String()}},
		{`UPDATE audit_events SET actor_id = '' WHERE actor_id = $1 AND chain_seq IS NOT NULL`, []any{userID.String()}},
		{`UPDATE audit_events SET approver_id = '' WHERE approver_id = $1 AND chain_seq IS NOT NULL`, []any{userID.String()}},
		{`DELETE FROM users WHERE id = $1`, []any{uid}},
	}
	for _, st := range stmts {
		if _, err := tx.Exec(ctx, st.sql, st.args...); err != nil {
			return fmt.Errorf("postgres: delete user cascade: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: delete user cascade: commit: %w", err)
	}
	return nil
}

const trustedCols = `id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at`

func scanTrusted(r pgx.Row) (theauth.TrustedDevice, error) {
	var (
		id, uid                pgtype.UUID
		hash                   []byte
		label, ua, ip          string
		created, used, expires pgtype.Timestamptz
		revoked                pgtype.Timestamptz
	)
	if err := r.Scan(&id, &uid, &hash, &label, &ua, &ip, &created, &used, &expires, &revoked); err != nil {
		return theauth.TrustedDevice{}, err
	}
	return theauth.TrustedDevice{
		ID: pgUUIDToULID(id), UserID: pgUUIDToULID(uid), TokenHash: hash, Label: label, UserAgent: ua, IP: ip,
		CreatedAt: tsToTime(created), LastUsedAt: tsToTime(used), ExpiresAt: tsToTime(expires),
		RevokedAt: tsToTimePtr(revoked),
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
	_, err := s.pool.Exec(ctx, `
INSERT INTO trusted_devices (id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		ulidToPgUUID(d.ID), ulidToPgUUID(d.UserID), d.TokenHash, d.Label, d.UserAgent, d.IP,
		created, used, d.ExpiresAt, timePtrToTs(d.RevokedAt))
	if err != nil {
		return fmt.Errorf("postgres: insert trusted device: %w", err)
	}
	return nil
}

// TrustedDeviceByTokenHash returns the record for userID and hash, revoked or expired rows included.
func (s *Store) TrustedDeviceByTokenHash(ctx context.Context, userID theauth.ULID, hash []byte) (*theauth.TrustedDevice, error) {
	d, err := scanTrusted(s.pool.QueryRow(ctx,
		`SELECT `+trustedCols+` FROM trusted_devices WHERE user_id = $1 AND token_hash = $2`, ulidToPgUUID(userID), hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: trusted device by hash: %w", err)
	}
	return &d, nil
}

// ListTrustedDevices returns the user's unrevoked, unexpired devices, newest first.
func (s *Store) ListTrustedDevices(ctx context.Context, userID theauth.ULID) ([]theauth.TrustedDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+trustedCols+` FROM trusted_devices
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY created_at DESC, id DESC`,
		ulidToPgUUID(userID), time.Now())
	if err != nil {
		return nil, fmt.Errorf("postgres: list trusted devices: %w", err)
	}
	defer rows.Close()
	var out []theauth.TrustedDevice
	for rows.Next() {
		d, err := scanTrusted(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: list trusted devices: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list trusted devices: %w", err)
	}
	return out, nil
}

// TouchTrustedDevice sets LastUsedAt.
func (s *Store) TouchTrustedDevice(ctx context.Context, id theauth.ULID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE trusted_devices SET last_used_at = $2 WHERE id = $1`, ulidToPgUUID(id), at)
	if err != nil {
		return fmt.Errorf("postgres: touch trusted device: %w", err)
	}
	return requireOne("touch trusted device", tag.RowsAffected())
}

// RevokeTrustedDevice revokes one live device owned by userID.
func (s *Store) RevokeTrustedDevice(ctx context.Context, userID, id theauth.ULID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE trusted_devices SET revoked_at = $3
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, ulidToPgUUID(id), ulidToPgUUID(userID), time.Now())
	if err != nil {
		return fmt.Errorf("postgres: revoke trusted device: %w", err)
	}
	return requireOne("revoke trusted device", tag.RowsAffected())
}

// RevokeUserTrustedDevices revokes every live device of userID and returns how many it revoked.
func (s *Store) RevokeUserTrustedDevices(ctx context.Context, userID theauth.ULID) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE trusted_devices SET revoked_at = $2
WHERE user_id = $1 AND revoked_at IS NULL`, ulidToPgUUID(userID), time.Now())
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke user trusted devices: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

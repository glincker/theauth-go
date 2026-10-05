package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var (
	_ theauth.TOTPReplayStorage     = (*Store)(nil)
	_ theauth.UserCountStorage      = (*Store)(nil)
	_ theauth.LoginThrottleCASStore = (*ThrottleStore)(nil)
)

// AdvanceTOTPStep records step as the user's last used TOTP step, returning false when it is not strictly newer.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID theauth.ULID, step int64) (bool, error) {
	uid := ulidToBytes(userID)
	res, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO totp_last_steps (user_id, step) VALUES (?, ?)`, uid, step)
	if err != nil {
		return false, fmt.Errorf("mysql: advance totp step: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true, nil
	}
	res, err = s.db.ExecContext(ctx, `UPDATE totp_last_steps SET step = ? WHERE user_id = ? AND step < ?`, step, uid, step)
	if err != nil {
		return false, fmt.Errorf("mysql: advance totp step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mysql: advance totp step: %w", err)
	}
	return n == 1, nil
}

// CountUsers returns the number of user rows.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("mysql: count users: %w", err)
	}
	return n, nil
}

// ThrottleStore is a MySQL-backed theauth.LoginThrottleStore shared by every process using the database.
type ThrottleStore struct{ s *Store }

// ThrottleStore returns a login throttle store backed by the same database.
func (s *Store) ThrottleStore() *ThrottleStore { return &ThrottleStore{s: s} }

// A zero time maps to 0 so entries without a block compare equal across a round trip.
func throttleMicro(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

func throttleTime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

func entryFromRow(failures int, last, blocked, expires int64) theauth.LoginThrottleEntry {
	return theauth.LoginThrottleEntry{
		Failures: failures, LastFailure: throttleTime(last), BlockedUntil: throttleTime(blocked), ExpiresAt: throttleTime(expires),
	}
}

// Get returns the entry for key.
func (t *ThrottleStore) Get(ctx context.Context, key string) (theauth.LoginThrottleEntry, bool, error) {
	var failures int
	var last, blocked, expires int64
	err := t.s.db.QueryRowContext(ctx, `
SELECT failures, last_failure, blocked_until, expires_at FROM throttle_entries WHERE entry_key = ?`, key).
		Scan(&failures, &last, &blocked, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return theauth.LoginThrottleEntry{}, false, nil
	}
	if err != nil {
		return theauth.LoginThrottleEntry{}, false, fmt.Errorf("mysql: throttle get: %w", err)
	}
	return entryFromRow(failures, last, blocked, expires), true, nil
}

// Set stores e under key unconditionally.
func (t *ThrottleStore) Set(ctx context.Context, key string, e theauth.LoginThrottleEntry) error {
	_, err := t.s.db.ExecContext(ctx, `
INSERT INTO throttle_entries (entry_key, failures, last_failure, blocked_until, expires_at) VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE failures = VALUES(failures), last_failure = VALUES(last_failure),
  blocked_until = VALUES(blocked_until), expires_at = VALUES(expires_at)`,
		key, e.Failures, throttleMicro(e.LastFailure), throttleMicro(e.BlockedUntil), throttleMicro(e.ExpiresAt))
	if err != nil {
		return fmt.Errorf("mysql: throttle set: %w", err)
	}
	return nil
}

// Delete removes key.
func (t *ThrottleStore) Delete(ctx context.Context, key string) error {
	if _, err := t.s.db.ExecContext(ctx, `DELETE FROM throttle_entries WHERE entry_key = ?`, key); err != nil {
		return fmt.Errorf("mysql: throttle delete: %w", err)
	}
	return nil
}

// CompareAndSwap writes next only when the stored entry still equals prev, or is absent when prevExists is false.
func (t *ThrottleStore) CompareAndSwap(ctx context.Context, key string, prev theauth.LoginThrottleEntry, prevExists bool, next theauth.LoginThrottleEntry) (bool, error) {
	if !prevExists {
		res, err := t.s.db.ExecContext(ctx, `
INSERT IGNORE INTO throttle_entries (entry_key, failures, last_failure, blocked_until, expires_at) VALUES (?, ?, ?, ?, ?)`,
			key, next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt))
		if err != nil {
			return false, fmt.Errorf("mysql: throttle compare and swap: %w", err)
		}
		n, err := res.RowsAffected()
		return n == 1, err
	}
	tx, err := t.s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("mysql: throttle compare and swap: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var failures int
	var last, blocked, expires int64
	err = tx.QueryRowContext(ctx, `
SELECT failures, last_failure, blocked_until, expires_at FROM throttle_entries WHERE entry_key = ? FOR UPDATE`, key).
		Scan(&failures, &last, &blocked, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("mysql: throttle compare and swap: %w", err)
	}
	if failures != prev.Failures || last != throttleMicro(prev.LastFailure) ||
		blocked != throttleMicro(prev.BlockedUntil) || expires != throttleMicro(prev.ExpiresAt) {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE throttle_entries SET failures = ?, last_failure = ?, blocked_until = ?, expires_at = ? WHERE entry_key = ?`,
		next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt), key); err != nil {
		return false, fmt.Errorf("mysql: throttle compare and swap: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("mysql: throttle compare and swap: %w", err)
	}
	return true, nil
}

// SweepExpired deletes entries whose ExpiresAt is at or before now and returns how many it removed.
func (t *ThrottleStore) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := t.s.db.ExecContext(ctx, `DELETE FROM throttle_entries WHERE expires_at <= ?`, now.UnixMicro())
	return rowsCount("throttle sweep", res, err)
}

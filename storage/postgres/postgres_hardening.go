package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5"
)

var (
	_ theauth.TOTPReplayStorage         = (*Store)(nil)
	_ theauth.UserCountStorage          = (*Store)(nil)
	_ theauth.LoginThrottleCASStore     = (*ThrottleStore)(nil)
	_ theauth.LoginThrottleEntryDeleter = (*ThrottleStore)(nil)
)

// AdvanceTOTPStep records step as the user's last used TOTP step, returning false when it is not strictly newer.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID theauth.ULID, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO totp_last_steps (user_id, step) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET step = EXCLUDED.step WHERE EXCLUDED.step > totp_last_steps.step`,
		ulidToPgUUID(userID), step)
	if err != nil {
		return false, fmt.Errorf("postgres: advance totp step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUsers returns the number of user rows.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: count users: %w", err)
	}
	return n, nil
}

// ThrottleStore is a Postgres-backed theauth.LoginThrottleStore shared by every process using the database.
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

// Get returns the entry for key.
func (t *ThrottleStore) Get(ctx context.Context, key string) (theauth.LoginThrottleEntry, bool, error) {
	var failures int
	var last, blocked, expires int64
	err := t.s.pool.QueryRow(ctx, `
SELECT failures, last_failure, blocked_until, expires_at FROM throttle_entries WHERE key = $1`, key).
		Scan(&failures, &last, &blocked, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return theauth.LoginThrottleEntry{}, false, nil
	}
	if err != nil {
		return theauth.LoginThrottleEntry{}, false, fmt.Errorf("postgres: throttle get: %w", err)
	}
	return theauth.LoginThrottleEntry{
		Failures: failures, LastFailure: throttleTime(last), BlockedUntil: throttleTime(blocked), ExpiresAt: throttleTime(expires),
	}, true, nil
}

// Set stores e under key unconditionally.
func (t *ThrottleStore) Set(ctx context.Context, key string, e theauth.LoginThrottleEntry) error {
	_, err := t.s.pool.Exec(ctx, `
INSERT INTO throttle_entries (key, failures, last_failure, blocked_until, expires_at) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO UPDATE SET failures = EXCLUDED.failures, last_failure = EXCLUDED.last_failure,
  blocked_until = EXCLUDED.blocked_until, expires_at = EXCLUDED.expires_at`,
		key, e.Failures, throttleMicro(e.LastFailure), throttleMicro(e.BlockedUntil), throttleMicro(e.ExpiresAt))
	if err != nil {
		return fmt.Errorf("postgres: throttle set: %w", err)
	}
	return nil
}

// Delete removes key.
func (t *ThrottleStore) Delete(ctx context.Context, key string) error {
	if _, err := t.s.pool.Exec(ctx, `DELETE FROM throttle_entries WHERE key = $1`, key); err != nil {
		return fmt.Errorf("postgres: throttle delete: %w", err)
	}
	return nil
}

// CompareAndSwap writes next only when the stored entry still equals prev, or is absent when prevExists is false.
func (t *ThrottleStore) CompareAndSwap(ctx context.Context, key string, prev theauth.LoginThrottleEntry, prevExists bool, next theauth.LoginThrottleEntry) (bool, error) {
	var n int64
	if prevExists {
		tag, err := t.s.pool.Exec(ctx, `
UPDATE throttle_entries SET failures = $1, last_failure = $2, blocked_until = $3, expires_at = $4
WHERE key = $5 AND failures = $6 AND last_failure = $7 AND blocked_until = $8 AND expires_at = $9`,
			next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt),
			key, prev.Failures, throttleMicro(prev.LastFailure), throttleMicro(prev.BlockedUntil), throttleMicro(prev.ExpiresAt))
		if err != nil {
			return false, fmt.Errorf("postgres: throttle compare and swap: %w", err)
		}
		n = tag.RowsAffected()
	} else {
		tag, err := t.s.pool.Exec(ctx, `
INSERT INTO throttle_entries (key, failures, last_failure, blocked_until, expires_at) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO NOTHING`,
			key, next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt))
		if err != nil {
			return false, fmt.Errorf("postgres: throttle compare and swap: %w", err)
		}
		n = tag.RowsAffected()
	}
	return n == 1, nil
}

// DeleteLoginEntries removes every login backoff entry for ident across all client IPs.
func (t *ThrottleStore) DeleteLoginEntries(ctx context.Context, ident string) error {
	if _, err := t.s.pool.Exec(ctx, `DELETE FROM throttle_entries WHERE key LIKE $1 ESCAPE '!'`, loginEntryPattern(ident)); err != nil {
		return fmt.Errorf("postgres: throttle delete login entries: %w", err)
	}
	return nil
}

func loginEntryPattern(ident string) string {
	return "login:%|" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(ident)
}

// SweepExpired deletes entries whose ExpiresAt is at or before now and returns how many it removed.
func (t *ThrottleStore) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	tag, err := t.s.pool.Exec(ctx, `DELETE FROM throttle_entries WHERE expires_at <= $1`, now.UnixMicro())
	if err != nil {
		return 0, fmt.Errorf("postgres: throttle sweep: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

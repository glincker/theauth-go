package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.LoginThrottleCASStore = (*ThrottleStore)(nil)

// ThrottleStore is a SQLite-backed theauth.LoginThrottleStore shared by every process using the database.
type ThrottleStore struct{ s *Store }

// ThrottleStore returns a login throttle store backed by the same database and table prefix.
func (s *Store) ThrottleStore() *ThrottleStore { return &ThrottleStore{s: s} }

// zero time maps to 0 so entries without a block compare equal across a round trip.
func throttleMicro(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return toMicro(t)
}

func throttleTime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return fromMicro(v)
}

// Get returns the entry for key.
func (t *ThrottleStore) Get(ctx context.Context, key string) (theauth.LoginThrottleEntry, bool, error) {
	var failures int
	var last, blocked, expires int64
	err := t.s.db.QueryRowContext(ctx, t.s.q(`
SELECT failures, last_failure, blocked_until, expires_at FROM theauth_throttle_entries WHERE key = ?`), key).
		Scan(&failures, &last, &blocked, &expires)
	if err == sql.ErrNoRows {
		return theauth.LoginThrottleEntry{}, false, nil
	}
	if err != nil {
		return theauth.LoginThrottleEntry{}, false, wrap("throttle get", err)
	}
	return theauth.LoginThrottleEntry{
		Failures: failures, LastFailure: throttleTime(last), BlockedUntil: throttleTime(blocked), ExpiresAt: throttleTime(expires),
	}, true, nil
}

// Set stores e under key unconditionally.
func (t *ThrottleStore) Set(ctx context.Context, key string, e theauth.LoginThrottleEntry) error {
	_, err := t.s.db.ExecContext(ctx, t.s.q(`
INSERT INTO theauth_throttle_entries (key, failures, last_failure, blocked_until, expires_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET failures = excluded.failures, last_failure = excluded.last_failure,
  blocked_until = excluded.blocked_until, expires_at = excluded.expires_at`),
		key, e.Failures, throttleMicro(e.LastFailure), throttleMicro(e.BlockedUntil), throttleMicro(e.ExpiresAt))
	return wrap("throttle set", err)
}

// Delete removes key.
func (t *ThrottleStore) Delete(ctx context.Context, key string) error {
	_, err := t.s.db.ExecContext(ctx, t.s.q(`DELETE FROM theauth_throttle_entries WHERE key = ?`), key)
	return wrap("throttle delete", err)
}

// CompareAndSwap writes next only when the stored entry still equals prev, or is absent when prevExists is false.
func (t *ThrottleStore) CompareAndSwap(ctx context.Context, key string, prev theauth.LoginThrottleEntry, prevExists bool, next theauth.LoginThrottleEntry) (bool, error) {
	var res sql.Result
	var err error
	if prevExists {
		res, err = t.s.db.ExecContext(ctx, t.s.q(`
UPDATE theauth_throttle_entries SET failures = ?, last_failure = ?, blocked_until = ?, expires_at = ?
WHERE key = ? AND failures = ? AND last_failure = ? AND blocked_until = ? AND expires_at = ?`),
			next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt),
			key, prev.Failures, throttleMicro(prev.LastFailure), throttleMicro(prev.BlockedUntil), throttleMicro(prev.ExpiresAt))
	} else {
		res, err = t.s.db.ExecContext(ctx, t.s.q(`
INSERT INTO theauth_throttle_entries (key, failures, last_failure, blocked_until, expires_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (key) DO NOTHING`),
			key, next.Failures, throttleMicro(next.LastFailure), throttleMicro(next.BlockedUntil), throttleMicro(next.ExpiresAt))
	}
	if err != nil {
		return false, wrap("throttle compare and swap", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrap("throttle compare and swap", err)
	}
	return n == 1, nil
}

// SweepExpired deletes entries whose ExpiresAt is at or before now and returns how many it removed.
func (t *ThrottleStore) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := t.s.db.ExecContext(ctx, t.s.q(`DELETE FROM theauth_throttle_entries WHERE expires_at <= ?`), toMicro(now))
	return rowsOrErr("throttle sweep", res, err)
}

// Package throttle implements login and MFA attempt limiting: per (IP,
// identifier) exponential backoff after a grace period, plus per-key
// lockout with automatic expiry. Decisions are made from stored counters
// only, so callers can consult it before any password hashing and unknown
// identifiers cost the same as known ones.
package throttle

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Entry is one throttle record. ExpiresAt is when the record may be dropped.
type Entry struct {
	Failures     int
	LastFailure  time.Time
	BlockedUntil time.Time
	ExpiresAt    time.Time
}

// Store persists throttle entries. Implementations must be safe for
// concurrent use; the Limiter serializes read-modify-write cycles itself
// within one process.
type Store interface {
	Get(ctx context.Context, key string) (Entry, bool, error)
	Set(ctx context.Context, key string, e Entry) error
	Delete(ctx context.Context, key string) error
}

// CASStore is an optional Store capability for stores shared across
// processes. CompareAndSwap writes next only when the stored entry still
// equals prev (or is absent when prevExists is false) and reports whether it
// did, so concurrent writers retry instead of overwriting each other.
type CASStore interface {
	Store
	CompareAndSwap(ctx context.Context, key string, prev Entry, prevExists bool, next Entry) (bool, error)
}

// Config holds every threshold. Zero values are replaced by defaults in
// WithDefaults.
type Config struct {
	GraceFailures   int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	ResetAfter      time.Duration
	UserMaxFailures int
	UserLockout     time.Duration
	MFAMaxFailures  int
	MFALockout      time.Duration
}

// WithDefaults returns c with zero fields set to the library defaults.
func (c Config) WithDefaults() Config {
	if c.GraceFailures <= 0 {
		c.GraceFailures = 3
	}
	if c.BaseDelay <= 0 {
		c.BaseDelay = time.Second
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = 15 * time.Minute
	}
	if c.ResetAfter <= 0 {
		c.ResetAfter = 15 * time.Minute
	}
	if c.UserMaxFailures <= 0 {
		c.UserMaxFailures = 10
	}
	if c.UserLockout <= 0 {
		c.UserLockout = 15 * time.Minute
	}
	if c.MFAMaxFailures <= 0 {
		c.MFAMaxFailures = 5
	}
	if c.MFALockout <= 0 {
		c.MFALockout = 15 * time.Minute
	}
	return c
}

// BlockedError reports that an attempt was refused and for how long.
type BlockedError struct {
	RetryAfter time.Duration
	Locked     bool
}

// Error implements error.
func (e *BlockedError) Error() string {
	kind := "backoff"
	if e.Locked {
		kind = "lockout"
	}
	return fmt.Sprintf("throttle: %s active, retry in %s", kind, e.RetryAfter.Round(time.Second))
}

const casAttempts = 64

// Limiter applies Config over a Store.
type Limiter struct {
	store Store
	cfg   Config
	now   func() time.Time
	mu    sync.Mutex
}

// New builds a Limiter. A nil store selects a fresh in-memory store.
func New(store Store, cfg Config) *Limiter {
	if store == nil {
		store = NewMemoryStore(0)
	}
	return &Limiter{store: store, cfg: cfg.WithDefaults(), now: time.Now}
}

// SetClock replaces the time source; tests only.
func (l *Limiter) SetClock(now func() time.Time) { l.now = now }

func loginKey(ip, ident string) string { return "login:" + ip + "|" + ident }
func userKey(ident string) string      { return "user:" + ident }
func mfaKey(userID string) string      { return "mfa:" + userID }

// CheckLogin refuses the attempt when the (ip, ident) backoff or the
// per-identifier lockout is active. It never inspects credentials.
func (l *Limiter) CheckLogin(ctx context.Context, ip, ident string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.blocked(ctx, userKey(ident), now, true); err != nil {
		return err
	}
	return l.blocked(ctx, loginKey(ip, ident), now, false)
}

// RecordLoginFailure counts a failed password attempt against the
// (ip, ident) backoff and the per-identifier lockout.
func (l *Limiter) RecordLoginFailure(ctx context.Context, ip, ident string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.bump(ctx, loginKey(ip, ident), now, false, func(e *Entry) {
		if over := e.Failures - l.cfg.GraceFailures; over > 0 {
			e.BlockedUntil = now.Add(l.backoff(over))
		}
	}); err != nil {
		return err
	}
	return l.bump(ctx, userKey(ident), now, true, func(e *Entry) {
		if e.Failures >= l.cfg.UserMaxFailures {
			e.BlockedUntil = now.Add(l.cfg.UserLockout)
		}
	})
}

// RecordLoginSuccess clears the (ip, ident) backoff after a good login.
func (l *Limiter) RecordLoginSuccess(ctx context.Context, ip, ident string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.store.Delete(ctx, loginKey(ip, ident)); err != nil {
		return fmt.Errorf("throttle: clear login entry: %w", err)
	}
	if err := l.store.Delete(ctx, userKey(ident)); err != nil {
		return fmt.Errorf("throttle: clear user entry: %w", err)
	}
	return nil
}

// CheckMFA refuses a second-factor attempt while the user is locked out.
func (l *Limiter) CheckMFA(ctx context.Context, userID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.blocked(ctx, mfaKey(userID), l.now(), true)
}

// RecordMFAFailure counts a bad TOTP or recovery code against the user,
// independent of which pending session carried it.
func (l *Limiter) RecordMFAFailure(ctx context.Context, userID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	return l.bump(ctx, mfaKey(userID), now, true, func(e *Entry) {
		if e.Failures >= l.cfg.MFAMaxFailures {
			e.BlockedUntil = now.Add(l.cfg.MFALockout)
		}
	})
}

// RecordMFASuccess clears the user's MFA failure counter.
func (l *Limiter) RecordMFASuccess(ctx context.Context, userID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.store.Delete(ctx, mfaKey(userID)); err != nil {
		return fmt.Errorf("throttle: clear mfa entry: %w", err)
	}
	return nil
}

// UnlockIdentifier clears the per-identifier lockout and the MFA lockout
// for an administrator override. Per-IP backoff entries age out on their own.
func (l *Limiter) UnlockIdentifier(ctx context.Context, ident, userID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.store.Delete(ctx, userKey(ident)); err != nil {
		return fmt.Errorf("throttle: unlock identifier: %w", err)
	}
	if userID != "" {
		if err := l.store.Delete(ctx, mfaKey(userID)); err != nil {
			return fmt.Errorf("throttle: unlock mfa: %w", err)
		}
	}
	return nil
}

func (l *Limiter) backoff(over int) time.Duration {
	d := l.cfg.BaseDelay
	for i := 1; i < over; i++ {
		d *= 2
		if d >= l.cfg.MaxDelay {
			return l.cfg.MaxDelay
		}
	}
	if d > l.cfg.MaxDelay {
		return l.cfg.MaxDelay
	}
	return d
}

func (l *Limiter) blocked(ctx context.Context, key string, now time.Time, locked bool) error {
	e, ok, err := l.store.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("throttle: read %s: %w", kindOf(key), err)
	}
	if ok && e.BlockedUntil.After(now) {
		return &BlockedError{RetryAfter: e.BlockedUntil.Sub(now), Locked: locked}
	}
	return nil
}

// bump increments the failure counter, restarting it when the previous
// window or lockout has lapsed, then lets apply set BlockedUntil.
func (l *Limiter) bump(ctx context.Context, key string, now time.Time, restartAfterLock bool, apply func(*Entry)) error {
	for attempt := 0; attempt < casAttempts; attempt++ {
		prev, ok, err := l.store.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("throttle: read %s: %w", kindOf(key), err)
		}
		e := prev
		if !ok || !e.ExpiresAt.After(now) || (restartAfterLock && lapsed(e, now)) {
			e = Entry{}
		}
		e.Failures++
		e.LastFailure = now
		apply(&e)
		e.ExpiresAt = e.LastFailure.Add(l.cfg.ResetAfter)
		if e.BlockedUntil.After(e.ExpiresAt) {
			e.ExpiresAt = e.BlockedUntil.Add(l.cfg.ResetAfter)
		}
		cas, isCAS := l.store.(CASStore)
		if !isCAS {
			if err := l.store.Set(ctx, key, e); err != nil {
				return fmt.Errorf("throttle: write %s: %w", kindOf(key), err)
			}
			return nil
		}
		swapped, err := cas.CompareAndSwap(ctx, key, prev, ok, e)
		if err != nil {
			return fmt.Errorf("throttle: write %s: %w", kindOf(key), err)
		}
		if swapped {
			return nil
		}
	}
	return fmt.Errorf("throttle: write %s: too much contention", kindOf(key))
}

// lapsed reports a lockout that has fully expired, so the next failure
// starts a fresh count instead of re-locking on the first miss.
func lapsed(e Entry, now time.Time) bool {
	return !e.BlockedUntil.After(now) && !e.BlockedUntil.IsZero()
}

func kindOf(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i]
		}
	}
	return strconv.Quote(key)
}

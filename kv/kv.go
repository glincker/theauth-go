// Package kv defines the small interfaces theauth uses for state that must be
// shared between replicas: rate-limit counters, replay caches (DPoP jti) and
// short-lived caches (Client ID Metadata Documents).
//
// Three adapters ship with the library:
//
//   - the in-process memory adapter in this package (the default),
//   - kv/sqlkv, which stores everything in one table of the database you
//     already run (Postgres, MySQL or SQLite),
//   - kv/redis, which talks to Redis through a one-method client interface so
//     the library takes no hard dependency on a Redis driver.
//
// You can also implement any of the interfaces yourself. The memory adapter
// keeps today's single-process behavior; with more than one replica pick a
// shared adapter so limits and replay protection hold across instances.
package kv

import (
	"context"
	"math"
	"time"
)

// Cache is a byte-oriented key/value store with per-key TTLs. Implementations
// must be safe for concurrent use. Keys are chosen by the library and are
// already namespaced (for example "rl:ip:203.0.113.7"); adapters should not
// reinterpret them.
type Cache interface {
	// Get returns the value for key. ok is false when the key is absent or
	// expired.
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)

	// Set stores value under key, replacing any previous value and counter.
	// A ttl of zero or less means the entry never expires.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// SetNX stores value only when key is absent or expired and reports
	// whether it stored. It must be atomic: of N concurrent callers exactly
	// one gets true.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (stored bool, err error)

	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error

	// Incr atomically adds one to the counter at key and returns the new
	// value. When the key is absent or expired the counter starts at 1 and
	// ttl is applied; on later increments the original expiry is kept (fixed
	// window). A ttl of zero or less means the counter never expires.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// ReplayCache remembers one-time identifiers (DPoP proof jti, assertion jti)
// so a second presentation inside the window is rejected.
type ReplayCache interface {
	// Seen records key for ttl and reports whether it was already recorded.
	// It must be atomic: of N concurrent callers with the same key exactly
	// one gets false.
	Seen(ctx context.Context, key string, ttl time.Duration) (already bool, err error)
}

// Decision is the outcome of one RateLimiter.Allow call.
type Decision struct {
	// Allowed is true when the request may proceed.
	Allowed bool
	// Remaining is the budget left in the current window (best effort).
	Remaining int
	// RetryAfter is how long the caller should wait before trying again when
	// Allowed is false. Zero when Allowed is true.
	RetryAfter time.Duration
}

// RateLimiter limits events per key. Callers pass the policy on every call so
// one limiter instance serves many rules.
type RateLimiter interface {
	// Allow consumes one unit for key under a budget of limit events per
	// window. Errors mean the backend failed; callers decide whether to fail
	// open or closed (theauth fails open and logs).
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error)
}

// CacheReplay adapts a Cache into a ReplayCache using SetNX.
type CacheReplay struct{ Cache Cache }

// Seen implements ReplayCache.
func (c CacheReplay) Seen(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	stored, err := c.Cache.SetNX(ctx, key, []byte{1}, ttl)
	if err != nil {
		return false, err
	}
	return !stored, nil
}

// WindowLimiter is a fixed-window RateLimiter built on Cache.Incr. It is the
// limiter used with the SQL and Redis adapters. A fixed window admits up to
// twice the limit across a window boundary; that is the usual trade for one
// round trip per request.
type WindowLimiter struct {
	Cache  Cache
	Prefix string
}

// Allow implements RateLimiter.
func (l WindowLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error) {
	if limit <= 0 || window <= 0 {
		return Decision{Allowed: true}, nil
	}
	n, err := l.Cache.Incr(ctx, l.Prefix+key, window)
	if err != nil {
		return Decision{}, err
	}
	if n > int64(limit) {
		return Decision{Allowed: false, RetryAfter: window}, nil
	}
	// n <= limit here, so the difference is in [0, limit]. Clamp before
	// narrowing to int so the conversion is provably in range.
	remaining := int64(limit) - n
	if remaining > math.MaxInt32 {
		remaining = math.MaxInt32
	}
	return Decision{Allowed: true, Remaining: int(remaining)}, nil
}

// Stores bundles the three pluggable pieces. Any nil field means "use the
// in-process memory default" when handed to theauth.
type Stores struct {
	RateLimiter RateLimiter
	ReplayCache ReplayCache
	Cache       Cache
}

// FromCache builds Stores that all share one Cache backend: a fixed-window
// limiter, a SetNX replay cache and the cache itself. This is the usual way to
// plug in the SQL or Redis adapters.
func FromCache(c Cache) Stores {
	return Stores{
		RateLimiter: WindowLimiter{Cache: c, Prefix: "rl:"},
		ReplayCache: CacheReplay{Cache: c},
		Cache:       c,
	}
}

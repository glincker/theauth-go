package kv

import (
	"context"
	"sync"
	"time"
)

// DefaultMemoryMaxEntries bounds the memory adapter so a flood of unique keys
// cannot grow it without limit.
const DefaultMemoryMaxEntries = 100_000

// MemoryOption tunes NewMemory.
type MemoryOption func(*Memory)

// WithClock injects the time source (tests).
func WithClock(now func() time.Time) MemoryOption {
	return func(m *Memory) {
		if now != nil {
			m.now = now
		}
	}
}

// WithMaxEntries caps the number of live keys (default DefaultMemoryMaxEntries).
func WithMaxEntries(n int) MemoryOption {
	return func(m *Memory) {
		if n > 0 {
			m.max = n
		}
	}
}

type memEntry struct {
	value   []byte
	n       int64
	expires time.Time // zero = never
}

func (e *memEntry) expired(now time.Time) bool {
	return !e.expires.IsZero() && !now.Before(e.expires)
}

type bucket struct {
	tokens float64
	last   time.Time
	window time.Duration
}

// Memory is the default in-process adapter. It implements Cache, ReplayCache
// and RateLimiter (a token bucket, so bursts refill smoothly the way the
// pre-kv per-IP limiter did). State is per process. There is no background
// goroutine: expired entries are swept lazily when the map grows.
type Memory struct {
	now func() time.Time
	max int

	mu      sync.Mutex
	entries map[string]*memEntry
	buckets map[string]*bucket
}

// NewMemory returns an empty in-process store.
func NewMemory(opts ...MemoryOption) *Memory {
	m := &Memory{
		now:     time.Now,
		max:     DefaultMemoryMaxEntries,
		entries: map[string]*memEntry{},
		buckets: map[string]*bucket{},
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Stores returns a Stores value wired to this one instance.
func (m *Memory) Stores() Stores {
	return Stores{RateLimiter: m, ReplayCache: m, Cache: m}
}

func (m *Memory) live(key string, now time.Time) *memEntry {
	e, ok := m.entries[key]
	if !ok {
		return nil
	}
	if e.expired(now) {
		delete(m.entries, key)
		return nil
	}
	return e
}

func (m *Memory) put(key string, e *memEntry, now time.Time) {
	if _, exists := m.entries[key]; !exists && len(m.entries) >= m.max {
		m.sweepEntries(now)
		if len(m.entries) >= m.max {
			m.evictSoonest()
		}
	}
	m.entries[key] = e
}

func (m *Memory) sweepEntries(now time.Time) {
	for k, e := range m.entries {
		if e.expired(now) {
			delete(m.entries, k)
		}
	}
}

// evictSoonest drops the entry closest to expiry (never-expiring entries last).
func (m *Memory) evictSoonest() {
	var victim string
	var best time.Time
	found := false
	for k, e := range m.entries {
		exp := e.expires
		if exp.IsZero() {
			exp = time.Unix(1<<40, 0)
		}
		if !found || exp.Before(best) {
			victim, best, found = k, exp, true
		}
	}
	if found {
		delete(m.entries, victim)
	}
}

func (m *Memory) expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

// Get implements Cache.
func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.live(key, m.now())
	if e == nil {
		return nil, false, nil
	}
	return append([]byte(nil), e.value...), true, nil
}

// Set implements Cache.
func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.put(key, &memEntry{value: append([]byte(nil), value...), expires: m.expiry(now, ttl)}, now)
	return nil
}

// SetNX implements Cache.
func (m *Memory) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.live(key, now) != nil {
		return false, nil
	}
	m.put(key, &memEntry{value: append([]byte(nil), value...), expires: m.expiry(now, ttl)}, now)
	return true, nil
}

// Delete implements Cache.
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// Incr implements Cache.
func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if e := m.live(key, now); e != nil {
		e.n++
		return e.n, nil
	}
	m.put(key, &memEntry{n: 1, expires: m.expiry(now, ttl)}, now)
	return 1, nil
}

// Seen implements ReplayCache.
func (m *Memory) Seen(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	stored, err := m.SetNX(ctx, key, []byte{1}, ttl)
	return !stored, err
}

// Allow implements RateLimiter with a token bucket: capacity limit, refilled
// at limit/window per second.
func (m *Memory) Allow(_ context.Context, key string, limit int, window time.Duration) (Decision, error) {
	if limit <= 0 || window <= 0 {
		return Decision{Allowed: true}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	b, ok := m.buckets[key]
	if !ok {
		if len(m.buckets) >= m.max {
			m.sweepBuckets(now)
			if len(m.buckets) >= m.max {
				// Still full of active buckets: drop an arbitrary one rather
				// than grow without bound.
				for k := range m.buckets {
					delete(m.buckets, k)
					break
				}
			}
		}
		b = &bucket{tokens: float64(limit), last: now}
		m.buckets[key] = b
	}
	b.window = window
	rate := float64(limit) / window.Seconds()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * rate
		if b.tokens > float64(limit) {
			b.tokens = float64(limit)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return Decision{Allowed: true, Remaining: int(b.tokens)}, nil
	}
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return Decision{Allowed: false, RetryAfter: wait}, nil
}

// sweepBuckets removes buckets that have been idle long enough to be full
// again (their state is indistinguishable from a fresh bucket).
func (m *Memory) sweepBuckets(now time.Time) {
	for k, b := range m.buckets {
		if now.Sub(b.last) >= b.window {
			delete(m.buckets, k)
		}
	}
}

// Len reports the number of live cache entries and rate buckets (tests).
func (m *Memory) Len() (entries, buckets int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries), len(m.buckets)
}

// Package ratelimit holds the per-key request limiter and the trusted-proxy aware client IP helpers.
package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Keyed is an in-memory per-key sliding-window limiter. Each unique
// key (e.g. an IP or email) gets its own *rate.Limiter that allows N events
// per minute with the same burst budget.
//
// A background goroutine evicts limiters not used in the last evictAfter
// duration to keep memory bounded under attack. The whole struct is
// goroutine-safe.
//
// Perf re-audit 2026-06-21 (item 2): mu is now a sync.RWMutex so
// concurrent Allow calls on already-existing keys take a shared read lock
// for the map lookup and only upgrade to a write lock for new-key
// insertion. lastUsed is stored as atomic.Int64 (unix nanos) so the Allow
// hot path can update it without holding the write lock.
type Keyed struct {
	mu          sync.RWMutex
	limits      map[string]*limiterEntry
	perMinute   int
	evictAfter  time.Duration
	stop        chan struct{}
	stopOnce    sync.Once
	tickerEvery time.Duration
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastUsed atomic.Int64 // unix nanos; updated without holding mu
}

// New starts the GC goroutine. Callers should defer .Stop() in
// tests; in production these live for the process lifetime.
func New(perMinute int) *Keyed {
	return NewWith(perMinute, 10*time.Minute, time.Minute)
}

// NewWith is the testable variant, caller specifies GC timing.
func NewWith(perMinute int, evictAfter, tickerEvery time.Duration) *Keyed {
	k := &Keyed{
		limits:      make(map[string]*limiterEntry),
		perMinute:   perMinute,
		evictAfter:  evictAfter,
		stop:        make(chan struct{}),
		tickerEvery: tickerEvery,
	}
	go k.gcLoop()
	return k
}

// Allow reports whether key may proceed now.
func (k *Keyed) Allow(key string) bool {
	if key == "" {
		// Empty key = no limiter applied. Caller decided to skip this dimension.
		return true
	}
	// Fast path: entry already exists, take a shared read lock.
	k.mu.RLock()
	entry, ok := k.limits[key]
	k.mu.RUnlock()
	if ok {
		// Update lastUsed atomically without holding the write lock.
		entry.lastUsed.Store(time.Now().UnixNano())
		return entry.lim.Allow()
	}
	// Slow path: first request for this key; take the write lock.
	k.mu.Lock()
	// Re-check under write lock (another goroutine may have inserted it).
	entry, ok = k.limits[key]
	if !ok {
		// rate.Every(perMinute per minute) = 1 token every (60/perMinute) seconds.
		// Burst of perMinute lets a fresh client burn the full budget instantly,
		// after which it refills smoothly, matches what users intuit as "N/min".
		r := rate.Every(time.Minute / time.Duration(k.perMinute))
		entry = &limiterEntry{lim: rate.NewLimiter(r, k.perMinute)}
		entry.lastUsed.Store(time.Now().UnixNano())
		k.limits[key] = entry
	}
	k.mu.Unlock()
	return entry.lim.Allow()
}

func (k *Keyed) gcLoop() {
	t := time.NewTicker(k.tickerEvery)
	defer t.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
			cutoffNanos := time.Now().Add(-k.evictAfter).UnixNano()
			k.mu.Lock()
			for key, e := range k.limits {
				if e.lastUsed.Load() < cutoffNanos {
					delete(k.limits, key)
				}
			}
			k.mu.Unlock()
		}
	}
}

// Stop terminates the GC goroutine. Safe to call multiple times.
func (k *Keyed) Stop() {
	k.stopOnce.Do(func() { close(k.stop) })
}

// ClientIP returns the best-effort client IP for the request.
//
// X-Forwarded-For is consulted only when r.RemoteAddr belongs to one of the
// operator-configured trusted prefixes; with no proxy in front the allowlist
// is empty and the header is ignored, so a client cannot dodge per-IP limits
// by forging it (security audit H4, 2026-06-20).
//
// When the peer is a trusted proxy the header is read from the right: each
// proxy appends the address it received the request from, so only the entries
// at the right edge were written by infrastructure you control. The walk skips
// entries that are themselves trusted proxies and returns the first address
// that is not, which is the nearest hop a trusted proxy actually observed.
// Everything to the left of it is client-supplied and never trusted. If an
// entry is not a valid IP the walk stops and the connection address is
// returned. If every entry is a trusted proxy the leftmost one is returned.
// Multiple X-Forwarded-For header lines are treated as one comma-joined list.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	remoteHost := RemoteAddrHost(r)
	if len(trusted) == 0 || !RemoteIsTrusted(remoteHost, trusted) {
		return remoteHost
	}
	var hops []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(line, ",") {
			if p := strings.TrimSpace(part); p != "" {
				hops = append(hops, p)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			return remoteHost
		}
		addr = addr.Unmap()
		if !prefixesContain(trusted, addr) || i == 0 {
			return addr.String()
		}
	}
	return remoteHost
}

func prefixesContain(trusted []netip.Prefix, addr netip.Addr) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RemoteAddrHost strips the port from r.RemoteAddr; if the address has no
// port it is returned as-is.
func RemoteAddrHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RemoteIsTrusted reports whether the supplied IP literal belongs to any
// of the configured trusted prefixes. Malformed IPs are never trusted.
func RemoteIsTrusted(ipLiteral string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ipLiteral)
	if err != nil {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// EntryCount returns the live key count, for verifying GC behavior.
func (k *Keyed) EntryCount() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.limits)
}

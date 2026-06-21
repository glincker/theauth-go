package theauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter is an in-memory per-key sliding-window limiter. Each unique
// key (e.g. an IP or email) gets its own *rate.Limiter that allows N events
// per minute with the same burst budget.
//
// A background goroutine evicts limiters not used in the last evictAfter
// duration to keep memory bounded under attack. The whole struct is
// goroutine-safe.
type keyedLimiter struct {
	mu          sync.Mutex
	limits      map[string]*limiterEntry
	perMinute   int
	evictAfter  time.Duration
	stop        chan struct{}
	stopOnce    sync.Once
	tickerEvery time.Duration
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

// newKeyedLimiter starts the GC goroutine. Callers should defer .Stop() in
// tests; in production these live for the process lifetime.
func newKeyedLimiter(perMinute int) *keyedLimiter {
	return newKeyedLimiterWith(perMinute, 10*time.Minute, time.Minute)
}

// newKeyedLimiterWith is the testable variant, caller specifies GC timing.
func newKeyedLimiterWith(perMinute int, evictAfter, tickerEvery time.Duration) *keyedLimiter {
	k := &keyedLimiter{
		limits:      make(map[string]*limiterEntry),
		perMinute:   perMinute,
		evictAfter:  evictAfter,
		stop:        make(chan struct{}),
		tickerEvery: tickerEvery,
	}
	go k.gcLoop()
	return k
}

func (k *keyedLimiter) Allow(key string) bool {
	if key == "" {
		// Empty key = no limiter applied. Caller decided to skip this dimension.
		return true
	}
	k.mu.Lock()
	entry, ok := k.limits[key]
	if !ok {
		// rate.Every(perMinute per minute) = 1 token every (60/perMinute) seconds.
		// Burst of perMinute lets a fresh client burn the full budget instantly,
		// after which it refills smoothly, matches what users intuit as "N/min".
		r := rate.Every(time.Minute / time.Duration(k.perMinute))
		entry = &limiterEntry{lim: rate.NewLimiter(r, k.perMinute)}
		k.limits[key] = entry
	}
	entry.lastUsed = time.Now()
	k.mu.Unlock()
	return entry.lim.Allow()
}

func (k *keyedLimiter) gcLoop() {
	t := time.NewTicker(k.tickerEvery)
	defer t.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
			cutoff := time.Now().Add(-k.evictAfter)
			k.mu.Lock()
			for key, e := range k.limits {
				if e.lastUsed.Before(cutoff) {
					delete(k.limits, key)
				}
			}
			k.mu.Unlock()
		}
	}
}

// Stop terminates the GC goroutine. Safe to call multiple times.
func (k *keyedLimiter) Stop() {
	k.stopOnce.Do(func() { close(k.stop) })
}

// extractClientIPTrusting returns the best-effort client IP for the
// request. The X-Forwarded-For header is consulted ONLY when the incoming
// r.RemoteAddr belongs to one of the operator-configured trusted prefixes;
// on a public-internet deployment with no proxy in front, that allowlist
// is empty and XFF is ignored, so an attacker cannot trivially bypass
// per-IP rate limits by forging the header (security audit H4,
// 2026-06-20).
//
// When the request arrives from a trusted proxy the first segment of XFF
// (the original client) is returned. Otherwise the function returns the
// connection-level RemoteAddr without a port.
func extractClientIPTrusting(r *http.Request, trusted []netip.Prefix) string {
	remoteHost := remoteAddrHost(r)
	if len(trusted) > 0 && remoteIsTrusted(remoteHost, trusted) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	return remoteHost
}

// remoteAddrHost strips the port from r.RemoteAddr; if the address has no
// port it is returned as-is.
func remoteAddrHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteIsTrusted reports whether the supplied IP literal belongs to any
// of the configured trusted prefixes. Malformed IPs are never trusted.
func remoteIsTrusted(ipLiteral string, trusted []netip.Prefix) bool {
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

// RateLimitByIP returns a middleware that limits requests per source IP to
// perMinute per minute. Use on credential endpoints (signin, signup, forgot,
// reset). The limiter lives on the returned handler. Multiple calls produce
// independent buckets, so wire it once per route group at startup.
//
// X-Forwarded-For is honored only when r.RemoteAddr is inside one of the
// Config.TrustedProxies prefixes. Deployments behind a reverse proxy MUST
// opt in by listing the proxy network in TrustedProxies; the default is
// the empty allowlist (no XFF trust), which is the safe behavior on a
// direct public-internet bind (security audit H4, 2026-06-20).
func (a *TheAuth) RateLimitByIP(perMinute int) func(http.Handler) http.Handler {
	k := newKeyedLimiter(perMinute)
	trusted := a.trustedProxies
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIPTrusting(r, trusted)
			if !k.Allow(ip) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate_limited", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitByEmail returns a middleware that limits requests per email body
// field. Reads the JSON body up to 16 KiB, extracts "email", restores the body
// so downstream handlers can re-read it. Requests without a parseable email
// are passed through unlimited (handler will reject them on its own).
func (a *TheAuth) RateLimitByEmail(perMinute int) func(http.Handler) http.Handler {
	k := newKeyedLimiter(perMinute)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			_ = r.Body.Close()
			// Restore body for the downstream handler.
			r.Body = io.NopCloser(bytes.NewReader(buf))

			var body struct {
				Email string `json:"email"`
			}
			// Best-effort decode; if it fails, we don't have a key, pass through.
			if err := json.Unmarshal(buf, &body); err != nil || body.Email == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.ToLower(strings.TrimSpace(body.Email))
			if !k.Allow(key) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate_limited", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

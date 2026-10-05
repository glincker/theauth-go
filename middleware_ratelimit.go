package theauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
)

var extractClientIPTrusting = ratelimit.ClientIP

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
	k := ratelimit.New(perMinute)
	trusted := a.trustedProxies
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "ip"})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIPTrusting(r, trusted)
			if !k.Allow(ip) {
				blocked.Inc()
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusTooManyRequests, "rate_limited")
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
	k := ratelimit.New(perMinute)
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "email"})
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
			key := a.normalizeEmail(body.Email)
			if !k.Allow(key) {
				blocked.Inc()
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

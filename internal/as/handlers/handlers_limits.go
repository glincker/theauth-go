package handlers

// handlers_limits.go: per-IP and per-client request limits for the token,
// revoke, introspect, PAR, bc-authorize and device_authorization endpoints,
// plus the 503 mapping for the Argon2id concurrency cap.

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
)

const (
	limitWindow    = time.Minute
	maxLimitedBody = 1 << 16
)

// SetClientIP installs the function used to derive the client address for
// rate limiting. Root passes one that honors Config.TrustedProxies. The
// default is the connection address, which never trusts forwarded headers.
func (h *Handler) SetClientIP(fn func(*http.Request) string) {
	if fn != nil {
		h.clientIP = fn
	}
}

func (h *Handler) ipOf(r *http.Request) string {
	if h.clientIP != nil {
		return h.clientIP(r)
	}
	return ratelimit.RemoteAddrHost(r)
}

// limited wraps an endpoint with the configured request limits. It parses the
// form (body capped at 64 KiB) so it can read client_id, then hands the
// already-parsed request on; handlers that call ParseForm again see the cached
// values.
func (h *Handler) limited(next http.Handler) http.Handler {
	cfg := h.svc.Cfg.RateLimits
	if cfg == nil || (cfg.PerIPPerMinute < 0 && cfg.PerClientPerMinute < 0) {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if cfg.PerIPPerMinute > 0 {
			ip := h.ipOf(r)
			d, err := h.svc.Limiter.Allow(ctx, "as:ip:"+ip, cfg.PerIPPerMinute, limitWindow)
			switch {
			case err != nil:
				slog.Warn("theauth: AS rate limiter unavailable, failing open", "rule", "ip", "err", err.Error())
			case !d.Allowed:
				h.blocked("as_ip")
				writeRateLimited(w, d.RetryAfter)
				return
			}
		}
		if cfg.PerClientPerMinute > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, maxLimitedBody)
			// ParseForm caches its result, so a parse error must be answered
			// here: the handler's own ParseForm would see an empty form.
			if err := r.ParseForm(); err != nil {
				writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
				return
			}
			id, secret := parseClientCredentials(r)
			if id == "" {
				id = jwtPeekIss(r.PostFormValue("client_assertion"))
				secret = r.PostFormValue("client_assertion")
			}
			if id != "" && secret != "" {
				d, err := h.svc.Limiter.Allow(ctx, "as:client:"+id, cfg.PerClientPerMinute, limitWindow)
				switch {
				case err != nil:
					slog.Warn("theauth: AS rate limiter unavailable, failing open", "rule", "client", "err", err.Error())
				case !d.Allowed:
					h.blocked("as_client")
					writeRateLimited(w, d.RetryAfter)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) blocked(rule string) {
	h.svc.Hooks.Counter(obs.MetricRateLimitBlockedTotal, obs.Labels{obs.AttrRule: rule}).Inc()
}

func writeRateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := int(math.Ceil(retry.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeOAuthError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
}

// isBusy reports whether err is the Argon2id concurrency shed.
func isBusy(err error) bool { return errors.Is(err, models.ErrOAuthServerBusy) }

// writeBusy answers 503 temporarily_unavailable (RFC 6749 section 5.2 style).
func writeBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "server is busy, retry shortly")
}

package theauth

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/kv"
)

// Error codes written by the admission middleware. They match the codes the
// TypeScript library and the client SDKs (IsCSRFRejected, IsRateLimited) key on.
const (
	// CodeAdmissionRateLimited is the 429 code written by Admission.
	CodeAdmissionRateLimited = "RATE_LIMITED"
	// CodeAdmissionCSRFRejected is the 403 code written by Admission.
	CodeAdmissionCSRFRejected = "CSRF_REJECTED"
)

// AdmissionLimit is one tier's budget: Max requests per Window per client.
// A zero field takes the tier default.
type AdmissionLimit struct {
	Max    int
	Window time.Duration
}

// AdmissionLimits are the per-tier budgets. Defaults: Strict 30, Mutation 120
// and Read 300 requests per 60 seconds.
type AdmissionLimits struct {
	// Strict covers token, registration and authorization endpoints.
	Strict AdmissionLimit
	// Mutation covers every other POST, PUT, PATCH and DELETE route.
	Mutation AdmissionLimit
	// Read covers GET, HEAD and OPTIONS routes.
	Read AdmissionLimit
}

// AdmissionOptions configures Admission. The zero value enables the default
// tiered rate limits and the cross-site check.
type AdmissionOptions struct {
	// DisableRateLimit turns rate limiting off, for example when a gateway
	// already does it. The cross-site check still applies.
	DisableRateLimit bool
	// Limits overrides the default per-tier budgets.
	Limits AdmissionLimits
	// Skip returns true to leave a request out of rate limiting (health
	// checks, your own network). The cross-site check still applies.
	Skip func(r *http.Request) bool
	// Key replaces the default client key (client IP, then credential digest).
	// Return "" to fall back to the default for that request.
	Key func(r *http.Request) string
	// TrustedOrigins are extra origins (scheme://host[:port]) allowed to send
	// cookie-authenticated writes, on top of Config.BaseURL, the request's own
	// origin and Config.TrustedOrigins.
	TrustedOrigins []string
	// DisableCSRF turns the cross-site check off.
	DisableCSRF bool
}

type admissionTier int

const (
	tierStrict admissionTier = iota
	tierMutation
	tierRead
)

func (t admissionTier) String() string {
	switch t {
	case tierStrict:
		return "strict"
	case tierMutation:
		return "mutation"
	default:
		return "read"
	}
}

// admissionStrictPaths are matched case-insensitively as an exact path, a
// prefix followed by "/", or a suffix, so a mount prefix does not matter.
var admissionStrictPaths = []string{
	"/mcp/token", "/mcp/register", "/mcp/authorize", "/authorize",
	"/oauth/token", "/oauth/register", "/oauth/par", "/oauth/revoke",
	"/oauth/introspect", "/oauth/device_authorization", "/oauth/bc-authorize",
}

func admissionTierOf(method, path string) admissionTier {
	p := strings.ToLower(path)
	for _, s := range admissionStrictPaths {
		if p == s || strings.HasPrefix(p, s+"/") || strings.HasSuffix(p, s) {
			return tierStrict
		}
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return tierRead
	}
	return tierMutation
}

func (l AdmissionLimit) orDefault(max int) AdmissionLimit {
	if l.Max <= 0 {
		l.Max = max
	}
	if l.Window <= 0 {
		l.Window = time.Minute
	}
	return l
}

// admissionKey picks the bucket: client IP, then a credential digest, then
// "unknown". The digest keeps raw credentials out of the counter store.
func admissionKey(r *http.Request, ip string) string {
	if ip != "" {
		return "ip:" + ip
	}
	cred := r.Header.Get("Authorization")
	if cred == "" {
		cred = r.Header.Get("Cookie")
	}
	if cred == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(cred))
	return "cred:" + hex.EncodeToString(sum[:8])
}

// Admission returns net/http middleware that runs before authentication and
// refuses an anonymous flood cheaply. It applies tiered per-client rate
// limits (429 with Retry-After) and a cross-site check for
// cookie-authenticated unsafe methods (403). Counters live in
// Config.Stores.RateLimiter when set, so replicas share budgets; otherwise a
// per-process memory limiter is used. A store failure lets the request
// through. Set Config.Admission to apply it to every route Mount registers.
func (a *TheAuth) Admission(opts AdmissionOptions) func(http.Handler) http.Handler {
	limits := [3]AdmissionLimit{
		tierStrict:   opts.Limits.Strict.orDefault(30),
		tierMutation: opts.Limits.Mutation.orDefault(120),
		tierRead:     opts.Limits.Read.orDefault(300),
	}
	var (
		once    sync.Once
		limiter kv.RateLimiter
	)
	getLimiter := func() kv.RateLimiter {
		once.Do(func() {
			if a.stores.RateLimiter != nil {
				limiter = a.stores.RateLimiter
				return
			}
			limiter = kv.WindowLimiter{Cache: kv.NewMemory()}
		})
		return limiter
	}
	trusted := append([]string(nil), a.trustedOrigins...)
	if extra, err := httpsec.NormalizeOrigins(opts.TrustedOrigins); err == nil {
		trusted = append(trusted, extra...)
	} else {
		slog.Warn("theauth: Admission ignoring invalid TrustedOrigins", "err", err.Error())
	}
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "admission"})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tier := admissionTierOf(r.Method, r.URL.Path)
			if !opts.DisableRateLimit && (opts.Skip == nil || !opts.Skip(r)) {
				key := ""
				if opts.Key != nil {
					key = opts.Key(r)
				}
				if key == "" {
					key = admissionKey(r, ratelimit.ClientIP(r, a.trustedProxies))
				}
				lim := limits[tier]
				d, err := getLimiter().Allow(r.Context(), "admit:"+tier.String()+":"+key, lim.Max, lim.Window)
				switch {
				case err != nil:
					slog.Warn("theauth: admission store failed, allowing request", "err", err.Error())
				case !d.Allowed:
					blocked.Inc()
					secs := int(math.Ceil(d.RetryAfter.Seconds()))
					if secs < 1 {
						secs = 1
					}
					w.Header().Set("Retry-After", strconv.Itoa(secs))
					a.jsonError(w, r, http.StatusTooManyRequests, CodeAdmissionRateLimited, "Too many requests")
					return
				}
			}
			if !opts.DisableCSRF && !a.admissionSameSite(r, trusted) {
				a.jsonError(w, r, http.StatusForbidden, CodeAdmissionCSRFRejected,
					"Cross-site request rejected for a cookie session")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// admissionSameSite reports whether r may proceed past the cross-site check.
// Safe methods, bearer callers and cookie-less requests are exempt. Fetch
// metadata saying same-origin or none is accepted; otherwise Origin (or
// Referer) must be the request's own origin, BaseURL or a trusted origin.
func (a *TheAuth) admissionSameSite(r *http.Request, trusted []string) bool {
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "same-origin", "none":
		return true
	}
	scheme := "http"
	if a.requestIsSecure(r) {
		scheme = "https"
	}
	own := scheme + "://" + r.Host
	all := make([]string, 0, len(trusted)+1)
	all = append(all, trusted...)
	if norm, err := httpsec.NormalizeOrigins([]string{own}); err == nil {
		all = append(all, norm...)
	}
	return httpsec.OriginAllowed(r, a.baseURL, all)
}

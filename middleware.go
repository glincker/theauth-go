package theauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	internalscim "github.com/glincker/theauth-go/v2/internal/scim"
	"github.com/go-chi/chi/v5"
)

// Authn reads the session cookie, validates it and adds the user and session to the request
// context. It does not reject anonymous requests; pair it with RequireAuth or RequirePendingOrFull.
func (a *TheAuth) Authn() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(a.cookieName)
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, user, err := a.validateSession(r.Context(), cookie.Value)
			if err != nil {
				// Validation failures are logged so DB outages do not look like anonymous users. The token is
				// never logged.
				slog.Warn("theauth: session validation failed", "err", err.Error())
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), userKey, user)
			ctx = context.WithValue(ctx, sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth runs Authn, then rejects requests without a full session. Pending 2FA sessions are
// refused; only the TOTP verify routes opt in to RequirePendingOrFull. Errors are RFC 7807
// problem+json with a WWW-Authenticate header. The codes are auth.unauthenticated and
// auth.step_up_required (a pending 2FA session that must complete the second factor).
func (a *TheAuth) RequireAuth() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				a.unauthenticated(w, r, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
				a.unauthenticated(w, r, "auth.step_up_required", "Session requires second-factor verification")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePendingOrFull accepts pending_2fa and full sessions. Only the TOTP verify and recovery
// routes use it.
func (a *TheAuth) RequirePendingOrFull() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := SessionFromContext(r.Context()); !ok {
				a.unauthenticated(w, r, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePermission enforces that the caller holds every named permission in
// session.active_organization_id. A session with no active organization gets 403
// rbac.no_active_org, and the system super_admin bypasses the check. With Config.RBAC nil it
// returns 500, since wiring the middleware without RBAC is a programming error.
func (a *TheAuth) RequirePermission(perms ...string) func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.rbacCfg == nil {
				a.problem(w, r, http.StatusInternalServerError, "rbac.disabled", "RBAC is not enabled in Config", "")
				return
			}
			user, okU := UserFromContext(r.Context())
			sess, okS := SessionFromContext(r.Context())
			if !okU || !okS || user == nil || sess == nil {
				a.unauthenticated(w, r, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
				a.unauthenticated(w, r, "auth.step_up_required", "Session requires second-factor verification")
				return
			}
			if sess.ActiveOrganizationID == nil {
				a.problem(w, r, http.StatusForbidden, "rbac.no_active_org", "Session has no active organization", "")
				return
			}
			cache, ok := rbac.PermissionCacheFromContext(r.Context())
			if !ok || (cache.OrgID != nil && *cache.OrgID != *sess.ActiveOrganizationID) {
				cache = &rbac.PermissionCache{OrgID: sess.ActiveOrganizationID}
			}
			cache.Once.Do(func() {
				roles, err := a.storage.RolesForUser(r.Context(), user.ID, nil)
				if err != nil {
					cache.Err = err
					return
				}
				for _, role := range roles {
					if role.Name == SystemRoleSuperAdmin {
						cache.SuperAdmin = true
						break
					}
				}
				if cache.SuperAdmin {
					cache.Set = map[string]struct{}{}
					return
				}
				list, err := a.storage.PermissionsForUser(r.Context(), user.ID, sess.ActiveOrganizationID)
				if err != nil {
					cache.Err = err
					return
				}
				cache.Set = rbac.SetFromList(list)
			})
			if cache.Err != nil {
				a.problem(w, r, http.StatusInternalServerError, "rbac.internal_error", "Permission lookup failed", "")
				return
			}
			ctx := rbac.WithPermissionCache(r.Context(), cache)
			if !cache.SuperAdmin {
				for _, p := range perms {
					if _, ok := cache.Set[p]; !ok {
						a.problem(w, r, http.StatusForbidden, "rbac.forbidden", "Caller lacks required permission: "+p, "")
						return
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

type scimCtxKey int

const (
	scimOrgIDKey scimCtxKey = iota
	scimTokenIDKey
	scimTokenRawKey
)

// scimAuth is the bearer middleware for /scim/v2/*. It enforces HTTPS (per
// SCIMConfig.RequireHTTPS), resolves the bearer token to an organization by hash, and stores the
// org and token row ID in the context for handlers and audit events.
func (a *TheAuth) scimAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.scimCfg == nil {
				writeSCIMMiddlewareError(w, http.StatusNotFound, "scim not enabled")
				return
			}
			if a.scimCfg.RequireHTTPS && !isHTTPS(r) {
				writeSCIMMiddlewareError(w, http.StatusForbidden, "scim requires https")
				return
			}
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				writeSCIMMiddlewareError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			result, err := a.AuthenticateSCIMToken(r.Context(), token)
			if err != nil {
				writeSCIMMiddlewareError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}
			ctx := context.WithValue(r.Context(), scimOrgIDKey, result.OrgID)
			ctx = context.WithValue(ctx, scimTokenIDKey, result.TokenID)
			ctx = context.WithValue(ctx, scimTokenRawKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func scimOrgFromContext(ctx context.Context) (ULID, bool) {
	v, ok := ctx.Value(scimOrgIDKey).(ULID)
	return v, ok
}

// scimTokenIDFromContext returns the SCIM token row ID set by scimAuth. It is the actor on SCIM audit events.
func scimTokenIDFromContext(ctx context.Context) ULID {
	if v, ok := ctx.Value(scimTokenIDKey).(ULID); ok {
		return v
	}
	return ULID{}
}

// isHTTPS reports whether the request came over TLS or through a proxy that sent X-Forwarded-Proto: https.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// writeSCIMMiddlewareError writes the SCIM error body from the bearer middleware. It re-marshals
// with the wire helpers in internal/scim, since the handler's writer is unexported there.
func writeSCIMMiddlewareError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", internalscim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(internalscim.NewError(status, "", detail))
}

// Handler returns a stdlib http.Handler serving every route Mount registers, for net/http users
// without chi. Paths keep their configured prefixes, so http.StripPrefix is unnecessary when the
// prefix matches the mount point.
func (a *TheAuth) Handler() http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

// securityMiddleware derives the Secure cookie flag per request, runs the Origin check ahead of
// every route, and sets Cache-Control: no-store on the auth routes and, when enabled, the security headers.
func (a *TheAuth) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.csrfDisabled && !httpsec.OriginAllowed(r, a.baseURL, a.trustedOrigins) {
			a.jsonError(w, r, http.StatusForbidden, "csrf_origin_rejected", "request origin is not trusted")
			return
		}
		secure := a.requestIsSecure(r)
		if secure {
			w = httpsec.NewCookieWriter(w)
		}
		if a.securityHeaders {
			httpsec.ApplySecurityHeaders(w.Header(), secure)
		}
		// Session and credential JSON (/auth/me, sign in, sign up, session list) must not be cached.
		// A handler that sets its own Cache-Control overrides this default.
		if httpsec.NoStorePath(r.URL.Path, a.pathPrefix) {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsSecure reports whether cookies for r must carry Secure. Config.SecureCookie wins;
// otherwise an https BaseURL, direct TLS, or X-Forwarded-Proto from a trusted proxy qualifies.
func (a *TheAuth) requestIsSecure(r *http.Request) bool {
	if a.secureCookie {
		return true
	}
	if u, err := url.Parse(a.baseURL); err == nil && strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if r.TLS != nil {
		return true
	}
	if len(a.trustedProxies) > 0 && ratelimit.RemoteIsTrusted(ratelimit.RemoteAddrHost(r), a.trustedProxies) {
		return strings.EqualFold(strings.TrimSpace(firstToken(r.Header.Get("X-Forwarded-Proto"))), "https")
	}
	return false
}

func firstToken(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		return v[:i]
	}
	return v
}

var extractClientIPTrusting = ratelimit.ClientIP

// clientIPOf resolves the client address honoring Config.TrustedProxies. Handlers use it for
// throttle keys, audit and session records so they match the rate limiter behind a proxy.
func (a *TheAuth) clientIPOf(r *http.Request) string {
	return extractClientIPTrusting(r, a.trustedProxies)
}

// newAllower returns the per-key limiter behind RateLimitByIP and RateLimitByEmail. With a shared
// limiter, keys carry a rule name and a per-call sequence so separate middleware instances keep
// separate budgets. A backend error fails open, so a limiter outage does not lock every user out of
// sign-in.
func (a *TheAuth) newAllower(rule string, perMinute int) func(context.Context, string) bool {
	if a.stores.RateLimiter == nil {
		k := ratelimit.New(perMinute)
		return func(_ context.Context, key string) bool { return k.Allow(key) }
	}
	prefix := "mw:" + rule + ":" + strconv.Itoa(int(a.rlSeq.Add(1))) + ":"
	lim := a.stores.RateLimiter
	return func(ctx context.Context, key string) bool {
		if key == "" {
			return true
		}
		d, err := lim.Allow(ctx, prefix+key, perMinute, time.Minute)
		if err != nil {
			slog.Warn("theauth: rate limiter backend failed, allowing request", "rule", rule, "err", err.Error())
			return true
		}
		return d.Allowed
	}
}

// RateLimitByIP limits requests per source IP to perMinute. Wire it once per route group at
// startup. X-Forwarded-For is honored only from Config.TrustedProxies; the empty default trusts no
// proxy (security audit H4).
func (a *TheAuth) RateLimitByIP(perMinute int) func(http.Handler) http.Handler {
	allow := a.newAllower("ip", perMinute)
	trusted := a.trustedProxies
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "ip"})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIPTrusting(r, trusted)
			if !allow(r.Context(), ip) {
				blocked.Inc()
				w.Header().Set("Retry-After", "60")
				a.jsonError(w, r, http.StatusTooManyRequests, CodeRateLimited, "rate_limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitByEmail limits requests per "email" field of the JSON body (read up to 16 KiB, then
// restored for the handler). Requests without a parseable email pass through; the handler rejects
// them.
func (a *TheAuth) RateLimitByEmail(perMinute int) func(http.Handler) http.Handler {
	allow := a.newAllower("email", perMinute)
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "email"})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(buf))

			var body struct {
				Email string `json:"email"`
			}
			if err := json.Unmarshal(buf, &body); err != nil || body.Email == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := a.normalizeEmail(body.Email)
			if !allow(r.Context(), key) {
				blocked.Inc()
				w.Header().Set("Retry-After", "60")
				a.jsonError(w, r, http.StatusTooManyRequests, CodeRateLimited, "rate_limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

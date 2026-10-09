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
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	internalscim "github.com/glincker/theauth-go/v2/internal/scim"
	"github.com/go-chi/chi/v5"
)

// Authn looks for a session cookie, validates it, and adds the user + session
// to the request context. Does NOT reject anonymous requests. Pair with
// RequireAuth (full) or RequirePendingOrFull (TOTP verify routes only).
func (a *TheAuth) Authn() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(a.cookieName)
			if err != nil || cookie.Value == "" {
				// No cookie present, silent anonymous request.
				next.ServeHTTP(w, r)
				return
			}
			sess, user, err := a.validateSession(r.Context(), cookie.Value)
			if err != nil {
				// Cookie present but validation failed: log so DB outages
				// don't masquerade as "user is anonymous". Token value is
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

// RequireAuth runs Authn, then rejects requests that don't have a FULL
// session. Pending_2fa sessions are treated as unauthorized here. The two
// TOTP verify routes opt in to RequirePendingOrFull instead.
//
// Errors are emitted as RFC 7807 problem+json with a WWW-Authenticate header
// per RFC 7235. Two failure codes are surfaced:
//
//   - auth.unauthenticated when no session cookie was presented or it failed
//     validation (cookie missing, expired, revoked, or storage rejected).
//   - auth.step_up_required when a pending_2fa session is present and the
//     caller must complete the second factor before proceeding.
//
// Frontends can distinguish the step-up case from a fresh login without
// special-casing string bodies.
func (a *TheAuth) RequireAuth() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				writeUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			// AuthLevel is "" on pre-v0.5 rows; treat as full for back compat.
			if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
				writeUnauthenticated(w, "auth.step_up_required", "Session requires second-factor verification")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePendingOrFull (v0.5) accepts both pending_2fa and full sessions.
// Used exclusively by /auth/totp/verify and /auth/totp/recovery so a user
// mid-step-up can complete the second factor.
func (a *TheAuth) RequirePendingOrFull() func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := SessionFromContext(r.Context()); !ok {
				writeUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePermission (v1.0) returns a middleware that enforces the caller
// holds every named permission inside session.active_organization_id. A
// session without active_organization_id is 403 rbac.no_active_org. A user
// with the system super_admin role bypasses the check entirely. The
// permission lookup hits storage once per request; subsequent middleware
// in the same chain hit the per-request cache attached to ctx.
//
// When Config.RBAC is nil the middleware short-circuits to 500: an admin
// trying to wire RequirePermission without enabling RBAC is a programming
// error worth surfacing loudly.
func (a *TheAuth) RequirePermission(perms ...string) func(http.Handler) http.Handler {
	authn := a.Authn()
	return func(next http.Handler) http.Handler {
		return authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.rbacCfg == nil {
				writeProblemJSON(w, http.StatusInternalServerError, "rbac.disabled", "RBAC is not enabled in Config", "")
				return
			}
			user, okU := UserFromContext(r.Context())
			sess, okS := SessionFromContext(r.Context())
			if !okU || !okS || user == nil || sess == nil {
				writeUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
				return
			}
			if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
				writeUnauthenticated(w, "auth.step_up_required", "Session requires second-factor verification")
				return
			}
			if sess.ActiveOrganizationID == nil {
				writeProblemJSON(w, http.StatusForbidden, "rbac.no_active_org", "Session has no active organization", "")
				return
			}
			cache, ok := rbac.PermissionCacheFromContext(r.Context())
			if !ok || (cache.OrgID != nil && *cache.OrgID != *sess.ActiveOrganizationID) {
				cache = &rbac.PermissionCache{OrgID: sess.ActiveOrganizationID}
			}
			cache.Once.Do(func() {
				// super_admin lookup (system role, org NULL).
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
				writeProblemJSON(w, http.StatusInternalServerError, "rbac.internal_error", "Permission lookup failed", "")
				return
			}
			ctx := rbac.WithPermissionCache(r.Context(), cache)
			if !cache.SuperAdmin {
				for _, p := range perms {
					if _, ok := cache.Set[p]; !ok {
						writeProblemJSON(w, http.StatusForbidden, "rbac.forbidden", "Caller lacks required permission: "+p, "")
						return
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

var (
	writeProblemJSON     = httpx.WriteProblemJSON
	writeUnauthenticated = httpx.WriteUnauthenticated
)

// ---------- SCIM bearer-auth middleware ----------

type scimCtxKey int

const (
	scimOrgIDKey scimCtxKey = iota
	scimTokenIDKey
	scimTokenRawKey
)

// scimAuth is the bearer-auth middleware for /scim/v2/*. It enforces
// HTTPS (per SCIMConfig.RequireHTTPS), extracts the Authorization:
// Bearer token, resolves it to an organization via sha256 lookup, and
// stashes both the orgID and the token row ID in the context for
// downstream handlers + audit emission.
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
			// AuthenticateSCIMToken now returns orgID + tokenID in one
			// storage round-trip (perf re-audit 2026-06-21, item 1).
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

// scimOrgFromContext returns the organization ID resolved by scimAuth.
func scimOrgFromContext(ctx context.Context) (ULID, bool) {
	v, ok := ctx.Value(scimOrgIDKey).(ULID)
	return v, ok
}

// scimTokenIDFromContext returns the SCIM token row ID resolved by
// scimAuth. Used as the actor for SCIM audit events.
func scimTokenIDFromContext(ctx context.Context) ULID {
	if v, ok := ctx.Value(scimTokenIDKey).(ULID); ok {
		return v
	}
	return ULID{}
}

// isHTTPS reports whether the request was served over TLS or arrived
// behind a TLS-terminating proxy that set X-Forwarded-Proto: https.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// writeSCIMMiddlewareError emits the SCIM error body shape from the
// bearer middleware path. PR F architecture reorg (2026-06-20): we
// can no longer call the package-private writeSCIMError because the
// handler moved into internal/scim/handlers; we re-marshal directly
// using the wire helpers exported from internal/scim.
func writeSCIMMiddlewareError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", internalscim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(internalscim.NewError(status, "", detail))
}

// Handler returns a stdlib http.Handler serving every route Mount would
// register, for consumers on net/http's ServeMux without chi. Routes keep
// their configured paths (Config.PathPrefix, default /auth/..., and /oauth/...),
// so no http.StripPrefix is needed when the prefix matches the mount point.
func (a *TheAuth) Handler() http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

// securityMiddleware applies per-request Secure cookie derivation and the
// Origin check ahead of every route Mount registers.
func (a *TheAuth) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.csrfDisabled && !httpsec.OriginAllowed(r, a.baseURL, a.trustedOrigins) {
			writeJSONError(w, http.StatusForbidden, "csrf_origin_rejected", "request origin is not trusted")
			return
		}
		if a.requestIsSecure(r) {
			w = httpsec.NewCookieWriter(w)
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsSecure reports whether cookies set for r must carry Secure.
// The explicit Config.SecureCookie flag wins; otherwise an https BaseURL,
// direct TLS, or X-Forwarded-Proto: https from a trusted proxy qualifies.
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

// newAllower returns the per-key limiter behind RateLimitByIP and
// RateLimitByEmail. Without Config.Stores.RateLimiter it is the in-process
// limiter, one independent bucket set per call. With a shared limiter the keys
// carry a rule name and a per-call sequence number, so separate middleware
// instances still get separate budgets and every replica that wires routes in
// the same order shares them. A backend error fails open: a limiter outage
// should not lock every user out of sign-in.
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
	allow := a.newAllower("ip", perMinute)
	trusted := a.trustedProxies
	blocked := a.hooks.Counter(MetricRateLimitBlockedTotal, Labels{AttrRule: "ip"})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIPTrusting(r, trusted)
			if !allow(r.Context(), ip) {
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
			if !allow(r.Context(), key) {
				blocked.Inc()
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

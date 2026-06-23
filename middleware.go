package theauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	internalscim "github.com/glincker/theauth-go/internal/scim"
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
			cache, ok := permissionCacheFromContext(r.Context())
			if !ok || (cache.orgID != nil && *cache.orgID != *sess.ActiveOrganizationID) {
				cache = &permissionCache{orgID: sess.ActiveOrganizationID}
			}
			cache.once.Do(func() {
				// super_admin lookup (system role, org NULL).
				roles, err := a.storage.RolesForUser(r.Context(), user.ID, nil)
				if err != nil {
					cache.err = err
					return
				}
				for _, role := range roles {
					if role.Name == SystemRoleSuperAdmin {
						cache.superAdmin = true
						break
					}
				}
				if cache.superAdmin {
					cache.set = map[string]struct{}{}
					return
				}
				list, err := a.storage.PermissionsForUser(r.Context(), user.ID, sess.ActiveOrganizationID)
				if err != nil {
					cache.err = err
					return
				}
				cache.set = permissionSetFromList(list)
			})
			if cache.err != nil {
				writeProblemJSON(w, http.StatusInternalServerError, "rbac.internal_error", "Permission lookup failed", "")
				return
			}
			ctx := withPermissionCache(r.Context(), cache)
			if !cache.superAdmin {
				for _, p := range perms {
					if _, ok := cache.set[p]; !ok {
						writeProblemJSON(w, http.StatusForbidden, "rbac.forbidden", "Caller lacks required permission: "+p, "")
						return
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

// writeProblemJSON emits a minimal RFC 7807 problem+json body. The admin
// package owns the richer variant with type URIs; this in-package helper
// keeps the middleware self-contained and avoids an import cycle.
func writeProblemJSON(w http.ResponseWriter, status int, code, detail, instance string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(problemBody(status, code, detail, instance))
}

// writeUnauthenticated emits a 401 with both the RFC 7807 body and an
// RFC 7235 WWW-Authenticate header. Session-cookie auth is the primary
// scheme; consumers using bearer tokens against the OAuth AS / mcpresource
// surface get the Bearer challenge from those packages instead.
func writeUnauthenticated(w http.ResponseWriter, code, detail string) {
	w.Header().Set("WWW-Authenticate", `Session realm="theauth", error="`+code+`"`)
	writeProblemJSON(w, http.StatusUnauthorized, code, detail, "")
}

func problemBody(status int, code, detail, instance string) []byte {
	// Tiny hand-built JSON encoder so the middleware avoids encoding/json
	// in the hot path. Six fields, two of which are optional. Numbers and
	// strings only, no escaping concerns since values are library-owned.
	b := []byte(`{"type":"https://theauth.dev/problems/`)
	b = append(b, code...)
	b = append(b, `","title":"`...)
	b = append(b, http.StatusText(status)...)
	b = append(b, `","status":`...)
	b = appendInt(b, status)
	b = append(b, `,"detail":`...)
	b = appendJSONString(b, detail)
	b = append(b, `,"code":"`...)
	b = append(b, code...)
	b = append(b, '"')
	if instance != "" {
		b = append(b, `,"instance":`...)
		b = appendJSONString(b, instance)
	}
	b = append(b, '}')
	return b
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		tmp[i] = '-'
	}
	return append(b, tmp[i:]...)
}

func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b = append(b, '\\', byte(r))
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if r < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hexDigit(byte(r>>4)), hexDigit(byte(r&0xf)))
			} else {
				b = appendRune(b, r)
			}
		}
	}
	return append(b, '"')
}

func hexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}

func appendRune(b []byte, r rune) []byte {
	const (
		t1 = 0x00
		tx = 0x80
		t2 = 0xC0
		t3 = 0xE0
		t4 = 0xF0
	)
	switch {
	case r < 0x80:
		return append(b, byte(r))
	case r < 0x800:
		return append(b, t2|byte(r>>6), tx|byte(r)&0x3F)
	case r < 0x10000:
		return append(b, t3|byte(r>>12), tx|byte(r>>6)&0x3F, tx|byte(r)&0x3F)
	default:
		return append(b, t4|byte(r>>18), tx|byte(r>>12)&0x3F, tx|byte(r>>6)&0x3F, tx|byte(r)&0x3F)
	}
}

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

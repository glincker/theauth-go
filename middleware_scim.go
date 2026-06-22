package theauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	internalscim "github.com/glincker/theauth-go/internal/scim"
)

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

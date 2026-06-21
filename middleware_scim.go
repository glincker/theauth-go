package theauth

import (
	"context"
	"net/http"
	"strings"
)

type scimCtxKey int

const (
	scimOrgIDKey scimCtxKey = iota
	scimTokenIDKey
	scimTokenRawKey
)

// scimAuth is the bearer-auth middleware for /scim/v2/*. It enforces
// HTTPS (per SCIMConfig.RequireHTTPS), extracts the Authorization: Bearer
// token, resolves it to an organization via sha256 lookup, and stashes
// both the orgID and the token row ID in the context for downstream
// handlers + audit emission.
func (a *TheAuth) scimAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.scimCfg == nil {
				writeSCIMError(w, http.StatusNotFound, "", "scim not enabled")
				return
			}
			if a.scimCfg.RequireHTTPS && !isHTTPS(r) {
				writeSCIMError(w, http.StatusForbidden, "", "scim requires https")
				return
			}
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				writeSCIMError(w, http.StatusUnauthorized, "", "missing bearer token")
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			orgID, err := a.AuthenticateSCIMToken(r.Context(), token)
			if err != nil {
				writeSCIMError(w, http.StatusUnauthorized, "", "invalid bearer token")
				return
			}
			tokID := a.scimTokenIDByPresented(r.Context(), token)
			ctx := context.WithValue(r.Context(), scimOrgIDKey, orgID)
			ctx = context.WithValue(ctx, scimTokenIDKey, tokID)
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

// scimTokenIDFromContext returns the SCIM token row ID resolved by scimAuth.
// Used as the actor for SCIM audit events.
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

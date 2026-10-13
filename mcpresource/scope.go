package mcpresource

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RequireScope returns middleware that admits a request only when the
// authenticated principal holds every listed scope. Mount it after
// (*Validator).Middleware, either router wide or around a single tool:
//
//	r.With(v.RequireScope("files:write")).Post("/tools/save", save)
//
// A principal missing a scope gets 403 with
//
//	WWW-Authenticate: Bearer error="insufficient_scope", scope="files:write",
//	    resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
//
// (RFC 6750 section 3.1) and a Denial JSON body. The scope parameter lists the
// scopes required, so a client can request exactly those on re-authorization.
// A request with no principal (Middleware did not run) is answered 401.
// Tokens bound with DPoP are answered with the DPoP scheme (RFC 9449).
func (v *Validator) RequireScope(scopes ...string) func(http.Handler) http.Handler {
	required := append([]string(nil), scopes...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				v.deny(w, r, "invalid_token", "no authenticated principal")
				return
			}
			if !hasAllScopes(p.Scope, required) {
				meta := protectedResourceMetadataURL(r, v.resourceURI)
				const desc = "the access token lacks a required scope"
				w.Header().Set("WWW-Authenticate", challenge(authScheme(p), "insufficient_scope", desc,
					[2]string{"scope", strings.Join(required, " ")},
					[2]string{"resource_metadata", meta}))
				WriteDenial(w, http.StatusForbidden, Denial{
					Error:            "insufficient_scope",
					ErrorDescription: desc,
					RequiredScopes:   required,
					ResourceMetadata: meta,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StepUp states the authentication strength and freshness a resource needs,
// for the RFC 9470 step-up challenge. The values are checked against the
// token's acr and auth_time claims.
type StepUp struct {
	// ACRValues lists acceptable authentication context class references.
	// The token's acr must equal one of them. Empty means no acr requirement.
	ACRValues []string
	// MaxAge is the oldest acceptable user authentication. The token's
	// auth_time must be no older than this. Zero means no age requirement
	// (max_age=0 "always re-authenticate" is not expressible; use a small
	// positive value such as time.Second).
	MaxAge time.Duration
}

// Satisfied reports whether the principal's acr and auth_time meet the
// requirement at the given instant. A missing acr or auth_time claim fails a
// requirement that depends on it.
func (s StepUp) Satisfied(p *Principal, now time.Time) bool {
	if p == nil {
		return false
	}
	if len(s.ACRValues) > 0 {
		match := false
		for _, a := range s.ACRValues {
			if p.ACR != "" && p.ACR == a {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if s.MaxAge > 0 {
		if p.AuthTime.IsZero() || now.Sub(p.AuthTime) > s.MaxAge {
			return false
		}
	}
	return true
}

// RequireStepUp returns middleware that answers 401 with an RFC 9470
// insufficient_user_authentication challenge when the principal's acr or
// auth_time does not satisfy s. Mount it after (*Validator).Middleware:
//
//	r.With(v.RequireStepUp(mcpresource.StepUp{
//	    ACRValues: []string{"urn:mfa"},
//	    MaxAge:    5 * time.Minute,
//	})).Post("/tools/transfer", transfer)
//
// The response carries
//
//	WWW-Authenticate: Bearer error="insufficient_user_authentication",
//	    acr_values="urn:mfa", max_age="300", resource_metadata="..."
//
// plus a Denial body whose step_up field repeats the requirement.
func (v *Validator) RequireStepUp(s StepUp) func(http.Handler) http.Handler {
	policy := StepUp{ACRValues: append([]string(nil), s.ACRValues...), MaxAge: s.MaxAge}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				v.deny(w, r, "invalid_token", "no authenticated principal")
				return
			}
			if policy.Satisfied(p, time.Now()) {
				next.ServeHTTP(w, r)
				return
			}
			meta := protectedResourceMetadataURL(r, v.resourceURI)
			const desc = "a higher authentication level or a fresher authentication is required"
			hint := &StepUpHint{ACRValues: policy.ACRValues}
			params := [][2]string{{"acr_values", strings.Join(policy.ACRValues, " ")}}
			if policy.MaxAge > 0 {
				hint.MaxAge = int64(policy.MaxAge / time.Second)
				params = append(params, [2]string{"max_age", strconv.FormatInt(hint.MaxAge, 10)})
			}
			params = append(params, [2]string{"resource_metadata", meta})
			w.Header().Set("WWW-Authenticate", challenge(authScheme(p), "insufficient_user_authentication", desc, params...))
			WriteDenial(w, http.StatusUnauthorized, Denial{
				Error:            "insufficient_user_authentication",
				ErrorDescription: desc,
				ResourceMetadata: meta,
				StepUp:           hint,
			})
		})
	}
}

// authScheme picks the challenge scheme: DPoP for a sender-constrained
// token, Bearer otherwise.
func authScheme(p *Principal) string {
	if p != nil && p.CnfJKT != "" {
		return "DPoP"
	}
	return "Bearer"
}

func hasAllScopes(have, need []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range need {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

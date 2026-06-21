package mcpresource

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Middleware is the chi-compatible middleware that validates the bearer token
// on every incoming request and attaches the parsed Principal to the request
// context. Compatible with chi.Router.Use, the net/http handler interface,
// and any router that accepts a func(http.Handler) http.Handler.
//
// On failure the middleware emits HTTP 401 with a WWW-Authenticate header
// per RFC 6750, including a resource_metadata pointer per RFC 9728 so MCP
// clients can discover the AS without out-of-band configuration.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.validateConfig(); err != nil {
			v.deny(w, r, "invalid_token", err.Error())
			return
		}
		token := extractBearer(r)
		if token == "" {
			v.deny(w, r, "invalid_token", "missing bearer token")
			return
		}
		principal, err := v.authenticate(r, token)
		if err != nil {
			v.deny(w, r, "invalid_token", err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), principal)))
	})
}

// authenticate runs the full validation chain for a token and returns a
// populated Principal on success. Steps:
//
//  1. Verify the JWT signature + structural claims against the JWKS cache.
//  2. Reject any aud mismatch up front (defence in depth: verifyJWT also
//     enforces this).
//  3. If the token carries an act chain or delegation_grant_id, walk the
//     chain against the AS introspection endpoint. Cached results live up to
//     cacheTTL; an AS-reported inactive flips the cache invalid immediately.
//  4. Build the Principal and return.
func (v *Validator) authenticate(r *http.Request, token string) (*Principal, error) {
	now := time.Now()
	claims, err := verifyJWT(token, v.resourceURI, v.jwks.PublicKey, now, v.clockSkew)
	if err != nil {
		return nil, err
	}
	principal := principalFromClaims(claims)
	if claims.Act != nil || claims.DelegationGrantID != "" {
		res, err := v.introspect.Lookup(token, v.resourceURI)
		if err != nil {
			return nil, err
		}
		if res == nil || !res.Active {
			v.introspect.Invalidate(token)
			return nil, errInactiveChain
		}
	}
	return principal, nil
}

// errInactiveChain is the canonical error for an AS-reported revoked chain.
var errInactiveChain = errInvalidTokenChain

var errInvalidTokenChain = newError("delegation chain inactive")

func newError(msg string) error { return &mcpError{msg: msg} }

type mcpError struct{ msg string }

func (e *mcpError) Error() string { return e.msg }

// principalFromClaims maps the parsed JWT claims into the public Principal
// shape. ActorChain walks innermost (Actor) to outermost (Subject); when no
// chain is present, ActorChain is empty and Subject == Actor.
func principalFromClaims(c *claims) *Principal {
	p := &Principal{
		Subject:           c.Sub,
		Actor:             c.Sub,
		Scope:             splitScope(c.Scope),
		ClientID:          c.ClientID,
		IssuedAt:          unix(c.Iat),
		ExpiresAt:         unix(c.Exp),
		Issuer:            c.Iss,
		Audience:          c.Aud,
		JWTID:             c.Jti,
		DelegationGrantID: c.DelegationGrantID,
	}
	if c.Act != nil {
		chain := flattenChain(c.Act)
		// chain[0] is the innermost actor; the outermost element of the JWT
		// remains in Subject (already set above).
		p.Actor = chain[0]
		p.ActorChain = chain
	}
	return p
}

// flattenChain walks the nested ActorClaim structure innermost first. The
// outermost element is the JWT sub (already populated separately).
func flattenChain(a *actorClaim) []string {
	var out []string
	for cur := a; cur != nil; cur = cur.Act {
		out = append(out, cur.Sub)
	}
	// Reverse so chain[0] is the innermost actor (the one currently acting).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func splitScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func unix(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0).UTC()
}

// extractBearer pulls the bearer token from the Authorization header. Returns
// "" when missing or not a Bearer scheme.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[len("Bearer "):])
}

// deny writes a 401 response with WWW-Authenticate + RFC 9728 metadata URL.
// The error code matches RFC 6750 section 3.1 (invalid_request,
// invalid_token, insufficient_scope).
func (v *Validator) deny(w http.ResponseWriter, r *http.Request, errCode, description string) {
	metadataURL := protectedResourceMetadataURL(r, v.resourceURI)
	value := "Bearer error=\"" + errCode + "\""
	if description != "" {
		value += ", error_description=\"" + escapeQuoted(description) + "\""
	}
	if metadataURL != "" {
		value += ", resource_metadata=\"" + metadataURL + "\""
	}
	w.Header().Set("WWW-Authenticate", value)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + errCode + `"}`))
}

// protectedResourceMetadataURL builds the /.well-known/oauth-protected-resource
// pointer per RFC 9728 section 3.3. The host comes from the incoming request
// so the URL is correct behind any proxy that sets the standard headers.
func protectedResourceMetadataURL(r *http.Request, resourceURI string) string {
	if resourceURI == "" {
		return ""
	}
	parsed, err := url.Parse(resourceURI)
	if err != nil || parsed.Host == "" {
		return ""
	}
	// Per RFC 9728 the metadata document lives at the resource origin under
	// /.well-known/oauth-protected-resource. Encode the resource identifier
	// path under the well-known prefix when one is configured.
	out := parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-protected-resource"
	if parsed.Path != "" && parsed.Path != "/" {
		out += parsed.Path
	}
	return out
}

func escapeQuoted(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

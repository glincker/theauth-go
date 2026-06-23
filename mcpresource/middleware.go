package mcpresource

import (
	"errors"
	"fmt"
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
		token, scheme := extractToken(r)
		if token == "" {
			v.deny(w, r, "invalid_token", "missing access token")
			return
		}
		principal, err := v.authenticate(r, token, scheme)
		if err != nil {
			// Per RFC 9449 section 7, a DPoP-bound token presented
			// without (or with an invalid) DPoP header should surface
			// the dpop wire error so the client can recover. The
			// fallback path still returns invalid_token for ordinary
			// failures.
			if isDPoPProofError(err) {
				v.denyDPoP(w, r, err.Error())
				return
			}
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
//  3. When the token carries an RFC 7800 cnf.jkt claim, REQUIRE an
//     inbound DPoP header and verify the proof against the request method
//     + URL + access-token hash, then check the proof JWK thumbprint
//     equals cnf.jkt. Tokens without cnf.jkt skip this step (Bearer
//     semantics).
//  4. If the token carries an act chain or delegation_grant_id, walk the
//     chain against the AS introspection endpoint. Cached results live up to
//     cacheTTL; an AS-reported inactive flips the cache invalid immediately.
//  5. Build the Principal and return.
func (v *Validator) authenticate(r *http.Request, token, scheme string) (*Principal, error) {
	now := time.Now()
	claims, err := verifyJWT(token, v.resourceURI, v.jwks.PublicKey, now, v.clockSkew)
	if err != nil {
		return nil, err
	}
	principal := principalFromClaims(claims)
	// DPoP binding: when the access token carries cnf.jkt the request
	// MUST also carry a DPoP header signed by the matching key. The
	// AS chose at issuance time whether to constrain; the resource
	// server enforces unconditionally.
	if claims.Cnf != nil && claims.Cnf.JKT != "" {
		if v.dpop == nil {
			return nil, fmt.Errorf("%w: resource server has no DPoP verifier configured", errDPoPMissingHeader)
		}
		if !strings.EqualFold(scheme, "dpop") {
			return nil, errDPoPMissingHeader
		}
		proof := r.Header.Get("DPoP")
		if proof == "" {
			return nil, errDPoPMissingHeader
		}
		jkt, err := v.dpop.verifyAndBind(proof, dpopVerifyParams{
			method:      r.Method,
			url:         requestURL(r),
			accessToken: token,
			requiredJKT: claims.Cnf.JKT,
			now:         now,
		})
		if err != nil {
			return nil, err
		}
		principal.CnfJKT = jkt
	}
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

// requestURL rebuilds the absolute URL the validator passes to the DPoP
// verifier. Honors X-Forwarded-Proto + X-Forwarded-Host so deployments
// behind a TLS-terminating proxy still produce the URL the client used.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host + r.URL.Path
}

// isDPoPProofError reports whether err is any of the DPoP sentinel
// errors. Used by the middleware to surface the right wire error.
func isDPoPProofError(err error) bool {
	switch {
	case errors.Is(err, errDPoPMalformed),
		errors.Is(err, errDPoPSignature),
		errors.Is(err, errDPoPMethodMismatch),
		errors.Is(err, errDPoPURIMismatch),
		errors.Is(err, errDPoPATHRequired),
		errors.Is(err, errDPoPATHMismatch),
		errors.Is(err, errDPoPProofExpired),
		errors.Is(err, errDPoPReplay),
		errors.Is(err, errDPoPJKTMismatch),
		errors.Is(err, errDPoPMissingHeader):
		return true
	}
	return false
}

// denyDPoP writes a 401 response with WWW-Authenticate using the DPoP
// scheme + invalid_dpop_proof / invalid_token error per RFC 9449 section
// 7.1. Distinct from deny() so clients can branch on the scheme to know
// whether to issue a fresh proof vs. a fresh token.
func (v *Validator) denyDPoP(w http.ResponseWriter, r *http.Request, description string) {
	metadataURL := protectedResourceMetadataURL(r, v.resourceURI)
	value := `DPoP error="invalid_token"`
	if description != "" {
		value += `, error_description="` + escapeQuoted(description) + `"`
	}
	if metadataURL != "" {
		value += `, resource_metadata="` + metadataURL + `"`
	}
	w.Header().Set("WWW-Authenticate", value)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid_token","scheme":"DPoP"}`))
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
	tok, _ := extractToken(r)
	return tok
}

// extractToken returns the access token and the scheme used to present
// it. Per RFC 9449 section 7.1 a DPoP-bound access token is presented
// via "Authorization: DPoP <token>"; vanilla bearer tokens continue
// using "Authorization: Bearer <token>". Other schemes are rejected.
func extractToken(r *http.Request) (string, string) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ""
	}
	lower := strings.ToLower(h)
	switch {
	case strings.HasPrefix(lower, "bearer "):
		return strings.TrimSpace(h[len("Bearer "):]), "Bearer"
	case strings.HasPrefix(lower, "dpop "):
		return strings.TrimSpace(h[len("DPoP "):]), "DPoP"
	}
	return "", ""
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

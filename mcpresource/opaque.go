package mcpresource

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WithOpaqueTokens lets the validator accept opaque (reference) access
// tokens in addition to JWTs. A token that is not JWT shaped is sent to the
// introspection endpoint set with WithIntrospection (RFC 7662) and the
// Principal is built from the answer. It needs WithIntrospection: without it
// every opaque token is refused and Diagnostics reports
// "opaque-no-introspection".
//
// A token is JWT shaped when it has exactly three non-empty base64url
// segments and the first starts like a JSON object ("eyJ"). Those tokens
// always take the JWT path, and a bad JWT is never retried as an opaque
// token. Anything else goes to introspection, unless it is empty, longer
// than 2048 bytes or holds characters outside the RFC 6750 token68 set, in
// which case it is refused without calling the AS.
//
// The same checks apply as for JWTs: the response must be active, carry an
// aud that contains the resource URI, and have an exp that is not past
// (with WithClockSkew). A response without aud or exp is refused. A refresh
// token (token_type refresh_token) is never accepted as an access token.
//
// DPoP: when the response carries cnf.jkt the request must present a
// matching DPoP proof exactly as for a bound JWT (it needs
// WithDPoPVerification). A response with token_type DPoP but no cnf.jkt is
// refused.
//
// Results are cached by SHA-256 of the token for WithCacheTTL, or for the
// AS Cache-Control max-age when that is a positive number of seconds. A
// token revoked at the AS therefore stays usable here until its cached
// answer expires. Lower WithCacheTTL (and the AS IntrospectionCacheTTL) to
// shrink that window.
func WithOpaqueTokens() Option {
	return func(v *Validator) { v.opaque = true }
}

// maxOpaqueTokenLen caps what is sent to the AS.
const maxOpaqueTokenLen = 2048

var (
	errOpaqueNoIntrospection = errors.New("mcpresource: opaque tokens need WithIntrospection")
	errOpaqueMalformed       = errors.New("mcpresource: malformed access token")
	errOpaqueInactive        = errors.New("mcpresource: token inactive")
)

// looksLikeJWT reports whether token has the compact JWS shape: two dots,
// three non-empty base64url segments, and a first segment that starts with
// "eyJ" (base64url of `{"`). It does not allocate.
func looksLikeJWT(token string) bool {
	if !strings.HasPrefix(token, "eyJ") {
		return false
	}
	dots := 0
	segLen := 0
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c == '.':
			if segLen == 0 {
				return false
			}
			dots++
			segLen = 0
		case isBase64URL(c):
			segLen++
		default:
			return false
		}
	}
	return dots == 2 && segLen > 0
}

func isBase64URL(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// validOpaqueChars reports whether token fits RFC 6750 token68.
func validOpaqueChars(token string) bool {
	if token == "" || len(token) > maxOpaqueTokenLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if isBase64URL(c) || c == '.' || c == '~' || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}

// authenticateOpaque validates a non JWT access token through introspection.
func (v *Validator) authenticateOpaque(r *http.Request, token, scheme string, now time.Time) (*Principal, error) {
	if v.introspectURI == "" {
		return nil, errOpaqueNoIntrospection
	}
	if !validOpaqueChars(token) {
		return nil, errOpaqueMalformed
	}
	res, err := v.introspect.Lookup(token, v.resourceURI)
	if err != nil {
		return nil, err
	}
	if res == nil || !res.Active {
		return nil, errOpaqueInactive
	}
	if tt := strings.ToLower(res.TokenType); tt != "" && tt != "bearer" && tt != "dpop" {
		return nil, fmt.Errorf("mcpresource: token_type %q is not an access token", res.TokenType)
	}
	if res.Exp == 0 || time.Unix(res.Exp, 0).Before(now.Add(-v.clockSkew)) {
		return nil, errors.New("mcpresource: token expired")
	}
	if res.Iat != 0 && time.Unix(res.Iat, 0).After(now.Add(v.clockSkew)) {
		return nil, errors.New("mcpresource: token iat in the future")
	}
	if v.resourceURI != "" && !res.Aud.contains(v.resourceURI) {
		return nil, fmt.Errorf("mcpresource: aud mismatch (got %q, want %q)", []string(res.Aud), v.resourceURI)
	}
	c := &claims{
		Iss: res.Iss, Sub: res.Sub, Aud: res.Aud, Exp: res.Exp, Iat: res.Iat,
		Jti: res.Jti, ClientID: res.ClientID, Scope: res.Scope,
		Act: res.Act, DelegationGrantID: res.DelegationGrantID,
		DeviceID: res.DeviceID, Acr: res.ACR, AuthTime: res.AuthTime, Amr: res.AMR,
		AuthorizationDetails: res.AuthorizationDetails,
	}
	principal := principalFromClaims(c)
	if v.resourceURI != "" {
		principal.Audience = v.resourceURI
	}
	details, err := parseAuthorizationDetails(res.AuthorizationDetails)
	if err != nil {
		return nil, err
	}
	principal.authorizationDetails = details
	jkt := ""
	if res.Cnf != nil {
		jkt = res.Cnf.JKT
	}
	if jkt == "" && strings.EqualFold(res.TokenType, "dpop") {
		return nil, errors.New("mcpresource: DPoP token without cnf.jkt")
	}
	if jkt != "" {
		bound, err := v.bindDPoP(r, token, scheme, jkt, now)
		if err != nil {
			return nil, err
		}
		principal.CnfJKT = bound
	}
	if err := v.checkRevocation(r, token, principal); err != nil {
		return nil, err
	}
	return principal, nil
}

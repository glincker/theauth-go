package as

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// compat.go: opt-in client compatibility behaviors (Config.ClientCompat).
//
// Real MCP clients (Claude Desktop, Cursor, ChatGPT and similar) routinely
// omit the RFC 8707 resource parameter, request scopes the server never
// advertised, use an ephemeral loopback port, and address a sub-path of the
// MCP server as the resource. Each flag below relaxes exactly one strict
// check. Every flag defaults to false, which keeps the strict behavior.

// ClientCompat is a set of independent switches that relax individual
// strictness checks for real-world OAuth clients. The zero value is fully
// strict. See docs/client-compat.md for the security tradeoffs.
type ClientCompat struct {
	// OptionalResource lets authorize, PAR, code and refresh token, and
	// jwt-bearer requests omit the resource parameter. An absent resource
	// defaults to the sole configured resource; with several configured
	// resources an absent resource is still invalid_target.
	OptionalResource bool

	// DropUnknownScopes drops requested scopes that are not in the client's
	// registered scope set or the resource catalog instead of rejecting the
	// request. The granted scope is returned in the token response scope
	// field. When scopes were requested and none remain, the request fails
	// with invalid_scope. On the refresh grant, scopes outside the original
	// grant are dropped the same way (a refresh never widens).
	DropUnknownScopes bool

	// LoopbackAnyPort matches a loopback redirect URI ignoring the port
	// (RFC 8252 section 7.3). It applies only when the registered URI is
	// http on 127.0.0.1 or [::1]; scheme, host, path and query must still
	// match exactly. Applied at /authorize, PAR and /token.
	LoopbackAnyPort bool

	// LoopbackAllowLocalhost additionally treats the host name "localhost"
	// as loopback for LoopbackAnyPort. Off by default because RFC 8252
	// section 8.3 discourages it (the name can resolve to a non-loopback
	// address). Has no effect unless LoopbackAnyPort is true.
	LoopbackAllowLocalhost bool

	// PathAudience lets a requested resource match a configured resource
	// when it is equal modulo a trailing slash, or when it has the
	// configured identifier as a path prefix on a "/" boundary. The issued
	// token aud is the configured canonical identifier, never the requested
	// sub-path.
	PathAudience bool
}

// resolveResource maps the resource parameter of a request to a configured
// resource and the audience to issue. An exact match (modulo one trailing
// slash) keeps the caller's spelling as the audience, which is the
// pre-existing behavior. A resource reached through OptionalResource or
// PathAudience always yields the configured canonical identifier.
func (s *Service) resolveResource(raw string) (models.ProtectedResource, string, error) {
	if raw == "" {
		if s.Cfg.ClientCompat.OptionalResource && len(s.Cfg.Resources) == 1 {
			r := s.Cfg.Resources[0]
			return r, r.Identifier, nil
		}
		return models.ProtectedResource{}, "", models.ErrOAuthInvalidResource
	}
	if r, ok := s.ResourceByIdentifier(raw); ok {
		return r, raw, nil
	}
	if s.Cfg.ClientCompat.PathAudience {
		var best models.ProtectedResource
		found := false
		for _, r := range s.Cfg.Resources {
			if !isPathChild(r.Identifier, raw) {
				continue
			}
			// Prefer the most specific (longest) configured prefix.
			if !found || len(r.Identifier) > len(best.Identifier) {
				best, found = r, true
			}
		}
		if found {
			return best, best.Identifier, nil
		}
	}
	return models.ProtectedResource{}, "", models.ErrOAuthInvalidResource
}

// isPathChild reports whether requested names a path below configured: it
// starts with the configured identifier followed by "/". Query, fragment,
// userinfo, dot segments and percent-encoded dots or slashes are refused so
// the prefix cannot be walked out of with traversal tricks.
func isPathChild(configured, requested string) bool {
	base := strings.TrimRight(configured, "/")
	if base == "" || !strings.HasPrefix(requested, base+"/") {
		return false
	}
	if strings.ContainsAny(requested, "?#\\") {
		return false
	}
	lower := strings.ToLower(requested)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return false
	}
	u, err := url.Parse(requested)
	if err != nil || u.User != nil {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// resourceMatchesGrant reports whether a resource parameter sent on the
// refresh grant is compatible with the resource the grant was issued for.
func (s *Service) resourceMatchesGrant(requested, granted string) bool {
	if requested == granted {
		return true
	}
	if !s.Cfg.ClientCompat.PathAudience {
		return false
	}
	r, _, err := s.resolveResource(requested)
	if err != nil {
		return false
	}
	return strings.TrimRight(r.Identifier, "/") == strings.TrimRight(granted, "/")
}

// narrowScopes validates the requested scope against the resource catalog.
// With DropUnknownScopes it instead drops scopes outside the catalog and
// the client's registered scope set, failing with invalid_scope only when
// nothing is left. client may be nil.
func (s *Service) narrowScopes(requested []string, resource models.ProtectedResource, client *models.OAuthClient) ([]string, error) {
	if !s.Cfg.ClientCompat.DropUnknownScopes || len(requested) == 0 {
		return validateScopeAgainstResource(requested, resource)
	}
	catalog := scopeSet(resource.Scopes)
	var allowed map[string]struct{}
	if client != nil {
		allowed = scopeSet(strings.Fields(client.Scope))
	}
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if catalog != nil {
			if _, ok := catalog[sc]; !ok {
				continue
			}
		}
		if allowed != nil {
			if _, ok := allowed[sc]; !ok {
				continue
			}
		}
		out = append(out, sc)
	}
	if len(out) == 0 {
		return nil, models.ErrOAuthInvalidScope
	}
	return out, nil
}

// narrowRefreshScopes returns the scope a refresh request is granted. A
// request that asks for scopes outside the original grant is rejected, or
// with DropUnknownScopes trimmed to the intersection.
func (s *Service) narrowRefreshScopes(requested, granted []string) ([]string, error) {
	if len(requested) == 0 {
		return granted, nil
	}
	if scopeSubset(requested, granted) {
		return requested, nil
	}
	if !s.Cfg.ClientCompat.DropUnknownScopes {
		return nil, models.ErrOAuthInvalidScope
	}
	have := scopeSet(granted)
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if _, ok := have[sc]; ok {
			out = append(out, sc)
		}
	}
	if len(out) == 0 {
		return nil, models.ErrOAuthInvalidScope
	}
	return out, nil
}

// scopeSet returns a set of the scopes, or nil when the slice is empty so
// callers can tell "no restriction" from "restricted to nothing".
func scopeSet(scopes []string) map[string]struct{} {
	if len(scopes) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(scopes))
	for _, sc := range scopes {
		m[sc] = struct{}{}
	}
	return m
}

// redirectURIRegistered reports whether uri matches a registered redirect
// URI: exactly, or under LoopbackAnyPort by the loopback port-agnostic rule.
func (s *Service) redirectURIRegistered(registered []string, uri string) bool {
	if redirectURIRegistered(registered, uri) {
		return true
	}
	if !s.Cfg.ClientCompat.LoopbackAnyPort || uri == "" {
		return false
	}
	for _, r := range registered {
		if s.loopbackEquivalent(r, uri) {
			return true
		}
	}
	return false
}

// loopbackEquivalent reports whether a and b are the same loopback http
// redirect URI up to the port (RFC 8252 section 7.3). Both must be loopback,
// and scheme, host, path and query must be identical.
func (s *Service) loopbackEquivalent(a, b string) bool {
	ua, ok := parseLoopback(a, s.Cfg.ClientCompat.LoopbackAllowLocalhost)
	if !ok {
		return false
	}
	ub, ok := parseLoopback(b, s.Cfg.ClientCompat.LoopbackAllowLocalhost)
	if !ok {
		return false
	}
	return ua.Hostname() == ub.Hostname() &&
		ua.EscapedPath() == ub.EscapedPath() &&
		ua.RawQuery == ub.RawQuery
}

// parseLoopback parses raw and returns it when it is an http URI on a
// loopback host with an absent or valid numeric port, no userinfo and no
// fragment.
func parseLoopback(raw string, allowLocalhost bool) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "::1":
	case "localhost":
		if !allowLocalhost {
			return nil, false
		}
	default:
		return nil, false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, false
		}
	}
	return u, true
}

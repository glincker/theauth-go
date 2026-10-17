package as

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// compat.go holds the opt-in client compatibility behaviors (Config.ClientCompat). Real MCP clients
// omit the resource parameter, request unadvertised scopes, use ephemeral loopback ports and
// address sub-paths. Each flag relaxes exactly one strict check and defaults to strict.

// ClientCompat is a set of independent switches that relax strictness checks. The zero value is
// fully strict. See docs/client-compat.md for the tradeoffs.
type ClientCompat struct {
	// OptionalResource lets requests omit the resource parameter. An absent resource defaults to the
	// sole configured resource; with several configured it stays invalid_target.
	OptionalResource bool

	// DropUnknownScopes drops requested scopes that the client or resource catalog does not know,
	// instead of rejecting the request. It fails with invalid_scope only when nothing remains. On
	// refresh it never widens the grant.
	DropUnknownScopes bool

	// LoopbackAnyPort ignores the port of a loopback redirect URI (RFC 8252 section 7.3). Only http on
	// 127.0.0.1 or [::1] qualifies; everything else must match exactly.
	LoopbackAnyPort bool

	// LoopbackAllowLocalhost also treats "localhost" as loopback for LoopbackAnyPort. Off by default:
	// RFC 8252 section 8.3 warns that the name may resolve off loopback.
	LoopbackAllowLocalhost bool

	// PathAudience lets a requested resource be a sub-path of a configured one, on a "/" boundary. The
	// issued aud is always the configured identifier, never the sub-path.
	PathAudience bool
}

// resolveResource maps a request's resource parameter to a configured resource and the audience to
// issue. An exact match keeps the caller's spelling; OptionalResource and PathAudience always yield
// the canonical identifier.
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

// isPathChild reports whether requested is a path below configured. Query, fragment, userinfo, dot
// segments and encoded dots or slashes are refused, so traversal tricks cannot escape the prefix.
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

// resourceMatchesGrant reports whether a refresh grant's resource parameter matches the resource
// the grant was issued for.
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

// narrowScopes validates requested scopes against the resource catalog. With DropUnknownScopes it
// drops unknown scopes instead, and fails only when none remain. client may be nil.
func (s *Service) narrowScopes(requested []string, resource models.ProtectedResource, client *models.OAuthClient) ([]string, error) {
	if s.OIDCEnabled() {
		// openid, profile and email are never part of a resource catalog.
		std, rest := splitOIDCScopes(requested)
		if len(std) > 0 {
			if len(rest) == 0 {
				return std, nil
			}
			out, err := s.narrowResourceScopes(rest, resource, client)
			if err != nil {
				return nil, err
			}
			return append(std, out...), nil
		}
	}
	return s.narrowResourceScopes(requested, resource, client)
}

func (s *Service) narrowResourceScopes(requested []string, resource models.ProtectedResource, client *models.OAuthClient) ([]string, error) {
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

// narrowRefreshScopes returns the scope a refresh is granted. Scopes outside the original grant are
// rejected, or dropped with DropUnknownScopes.
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

// scopeSet returns a set of the scopes, or nil for an empty slice so "no restriction" differs from
// "restricted to nothing".
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

// redirectURIRegistered reports whether uri matches a registered redirect URI, exactly or
// port-agnostically for loopback.
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

// loopbackEquivalent reports whether a and b are the same loopback http redirect URI up to the port
// (RFC 8252 section 7.3).
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

// parseLoopback returns raw when it is an http URI on a loopback host with an optional valid port
// and no userinfo or fragment.
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

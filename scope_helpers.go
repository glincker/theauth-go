package theauth

import (
	"errors"
	"strings"
)

// scope_helpers.go: scope string codec helpers shared by the root
// service_agent.go (PR C scope) and handlers_oauth_server.go (PR E
// scope). PR B architecture reorg (2026-06-20) moved the AS cluster
// into internal/as which has its own copy of these helpers; once
// service_agent / handlers move into their dedicated packages this
// file becomes dead and can be deleted.

// scopeJoin renders a scope slice as the space-separated form used in
// JWT claims, RFC 7591 client metadata, and Cache-Control responses.
func scopeJoin(scope []string) string { return strings.Join(scope, " ") }

// scopeSplit parses a space-separated scope string into a deduped
// slice preserving order of first occurrence.
func scopeSplit(s string) []string {
	parts := strings.Fields(s)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// validateScopeAgainstResource returns the intersection of requested
// and supported scopes; returns error if requested contains any scope
// outside the resource's catalog. Used by service_delegation.go (PR C
// scope); the AS cluster has its own copy inside internal/as. Both
// versions MUST stay in sync until PR C unifies them.
func validateScopeAgainstResource(requested []string, resource ProtectedResource) ([]string, error) {
	if len(requested) == 0 {
		return nil, errors.New("scope required")
	}
	if len(resource.Scopes) == 0 {
		return requested, nil
	}
	supported := map[string]struct{}{}
	for _, s := range resource.Scopes {
		supported[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := supported[s]; !ok {
			return nil, ErrOAuthInvalidScope
		}
		out = append(out, s)
	}
	return out, nil
}

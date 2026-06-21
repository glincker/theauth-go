package theauth

import (
	"strings"
)

// scope_helpers.go: scope string codec helpers used by the root
// handlers_oauth_server.go (PR E scope). PR C architecture reorg
// (2026-06-20) moved validateScopeAgainstResource and scopeJoin into
// internal/delegation + internal/as (each owns its own copy); only
// scopeSplit remains here because handlers_oauth_server.go still parses
// inbound form values before forwarding them to the AS service. The
// whole file goes away once handlers_oauth_server.go moves into a
// dedicated internal package (PR E scope).

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

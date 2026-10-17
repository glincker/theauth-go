// Package chain provides pure helpers for RFC 8693 actor chains: depth, scope subset, duration
// narrowing and act-claim construction. The helpers are deterministic and dependency free.
package chain

import "time"

// Actor mirrors the RFC 8693 section 4.1 actor claim, enough for depth and sub extraction. Callers
// convert to theauth.ActorClaim at the boundary.
type Actor struct {
	Sub string
	Act *Actor
}

// Depth returns the number of links in the actor chain. A token with no act claim has depth 1 (only
// the subject).
func Depth(act *Actor) int {
	depth := 1
	for cur := act; cur != nil; cur = cur.Act {
		depth++
	}
	return depth
}

// Prepend builds the actor chain after an exchange: the requesting actor becomes innermost. The
// input chain is not mutated.
func Prepend(newActorSub string, existing *Actor) *Actor {
	if existing == nil {
		return &Actor{Sub: newActorSub}
	}
	return &Actor{Sub: newActorSub, Act: existing}
}

// Walk visits each Actor innermost first until fn returns false. The root subject is not visited.
func Walk(act *Actor, fn func(a *Actor) bool) {
	for cur := act; cur != nil; cur = cur.Act {
		if !fn(cur) {
			return
		}
	}
}

// ScopeSubset reports whether every element of sub is in sup. It enforces strict narrowing at every exchange.
func ScopeSubset(sub, sup []string) bool {
	have := make(map[string]struct{}, len(sup))
	for _, s := range sup {
		have[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

// ScopeIntersect returns the intersection of a and b, preserving the order
// of first occurrence in a.
func ScopeIntersect(a, b []string) []string {
	have := make(map[string]struct{}, len(b))
	for _, s := range b {
		have[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := have[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// TightenDuration returns the earliest non-zero candidate expiry, so optional upper bounds can be
// passed directly. It returns the zero time when all inputs are zero.
func TightenDuration(candidates ...time.Time) time.Time {
	var out time.Time
	for _, c := range candidates {
		if c.IsZero() {
			continue
		}
		if out.IsZero() || c.Before(out) {
			out = c
		}
	}
	return out
}

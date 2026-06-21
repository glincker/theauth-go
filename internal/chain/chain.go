// Package chain provides pure helpers for RFC 8693 actor chain validation:
// depth counting, scope subset checking, duration narrowing, and act-claim
// construction. All functions are deterministic and dependency free so the
// token-exchange grant can call them without acquiring any state.
package chain

import "time"

// Actor mirrors the RFC 8693 section 4.1 actor claim shape sufficiently for
// depth + sub extraction. The chain package does not depend on the
// theauth.ActorClaim type to keep itself import-cycle free; callers convert
// between the two at the boundary.
type Actor struct {
	Sub string
	Act *Actor
}

// Depth returns the number of links in an actor chain rooted by the
// surrounding JWT's sub. A token without any act claim has depth 1 (just
// the subject); one nested act has depth 2; two nested acts have depth 3.
func Depth(act *Actor) int {
	depth := 1
	for cur := act; cur != nil; cur = cur.Act {
		depth++
	}
	return depth
}

// Prepend builds the new actor chain after a token exchange: the requesting
// actor (newActorSub) becomes the innermost actor; the existing chain
// follows. The returned pointer is fresh; the input chain is not mutated.
func Prepend(newActorSub string, existing *Actor) *Actor {
	if existing == nil {
		return &Actor{Sub: newActorSub}
	}
	return &Actor{Sub: newActorSub, Act: existing}
}

// Walk visits each Actor in the chain inward-to-outward order (innermost
// first) and invokes fn until it returns false or the chain is exhausted.
// The surrounding JWT's sub is not visited; callers handle the root subject
// separately because it has no "Sub" Actor wrapper.
func Walk(act *Actor, fn func(a *Actor) bool) {
	for cur := act; cur != nil; cur = cur.Act {
		if !fn(cur) {
			return
		}
	}
}

// ScopeSubset reports whether every element of sub is present in sup. Used
// at every token-exchange mint to enforce the strict-narrowing invariant
// across the chain.
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

// TightenDuration computes the strict-min of every supplied candidate exp,
// ignoring zero-valued times so callers can pass optional upper bounds. The
// duration of a token-exchange-minted access token is always the min of
// (subject_exp, now+DefaultDelegatedTokenTTL, now+grant.max_duration_seconds,
// now+AccessTokenTTL); use TightenDuration to compute that without branching.
//
// Returns the zero time if every input is zero.
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

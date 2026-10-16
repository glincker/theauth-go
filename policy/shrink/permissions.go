package shrink

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/glincker/theauth-go/v2/policy"
)

// internalActions are bookkeeping actions that are never calls by the agent.
var internalActions = map[string]struct{}{
	"agent.cascade.revoked": {},
	"delegation.create":     {},
	"delegation.granted":    {},
	"delegation.revoked":    {},
	"approval.request":      {},
	"approval.decided":      {},
}

// noGrantReasons are lowercase reason prefixes that mean no permission covered
// the call. The first is the policy evaluator's default deny reason.
var noGrantReasons = []string{
	"no matching allow statement",
	"no permission grants",
	"policy_no_matching_permission",
}

// Classify says how a row is treated by usage analysis. Denied rows count as
// "no grant" only when the reason says so; any other denial, a rate limit or an
// escalation is "other" and never proves a grant unused.
func Classify(r DecisionRow) RowClass {
	if strings.HasPrefix(r.Action, "audit.") {
		return ClassInternal
	}
	if _, ok := internalActions[r.Action]; ok {
		return ClassInternal
	}
	switch r.Result {
	case ResultAllowed:
		return ClassAllow
	case ResultDenied:
		reason := strings.ToLower(r.Reason)
		for _, p := range noGrantReasons {
			if strings.HasPrefix(reason, p) {
				return ClassDenyNoGrant
			}
		}
	}
	return ClassDenyOther
}

// extrasKey identifies everything about a permission except action and resource.
func extrasKey(p Permission) string {
	if len(p.Conditions) == 0 {
		return "null"
	}
	b, err := json.Marshal(p.Conditions)
	if err != nil {
		// Conditions hold only strings, so this cannot happen.
		return "invalid"
	}
	return string(b)
}

// atomKey is the identity of a single-action permission.
func atomKey(p Permission) string {
	return p.Resource + "\x00" + p.Action + "\x00" + extrasKey(p)
}

// Covers reports whether outer allows every (action, resource) that inner
// allows. It is built on policy.Match, so a wildcard in inner is covered only
// by an equal or broader wildcard in outer.
func Covers(outer, inner Permission) bool {
	return policy.Match(outer.Resource, inner.Resource) && policy.Match(outer.Action, inner.Action)
}

// firstMatch returns the index of the first permission matching the call, or
// -1. It is the engine's first-match order over policy.Match.
func firstMatch(perms []Permission, action, resource string) int {
	for i, p := range perms {
		if policy.Match(p.Action, action) && policy.Match(p.Resource, resource) {
			return i
		}
	}
	return -1
}

func clonePerm(p Permission) Permission {
	p.Conditions = slices.Clone(p.Conditions)
	return p
}

// Statements compacts single-action permissions into allow statements. Atoms
// that share a resource and conditions merge into one statement at the position
// of the first occurrence. The result is ready for a policy.Policy.
func Statements(perms []Permission) []policy.Statement {
	var out []policy.Statement
	at := map[string]int{}
	for _, p := range perms {
		key := p.Resource + "\x00" + extrasKey(p)
		if i, ok := at[key]; ok {
			if !slices.Contains(out[i].Actions, p.Action) {
				out[i].Actions = append(out[i].Actions, p.Action)
			}
			continue
		}
		at[key] = len(out)
		out = append(out, policy.Statement{
			Effect:     policy.Allow,
			Actions:    []string{p.Action},
			Resources:  []string{p.Resource},
			Conditions: slices.Clone(p.Conditions),
		})
	}
	return out
}

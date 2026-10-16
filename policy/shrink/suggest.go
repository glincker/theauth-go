package shrink

import (
	"slices"
	"strings"

	"github.com/glincker/theauth-go/v2/policy"
)

const defaultGeneralizeMin = 3

// parentOf returns the resource without its last ":" segment, or "" when the
// resource has no such parent or carries glob, escape or {var} syntax.
func parentOf(resource string) string {
	if strings.ContainsAny(resource, `*\{`) {
		return ""
	}
	i := strings.LastIndex(resource, ":")
	if i <= 0 {
		return ""
	}
	return resource[:i]
}

type group struct {
	parent  string
	action  string
	extras  Permission
	indexes []int
}

// SuggestShrink turns a usage analysis into a smaller permission set. It is
// pure and deterministic: the same analysis and options always give the same
// output, ordered as the granted list was.
//
// A permission is kept when it has at least MinObservations allowed calls, or
// when its only traffic was denied for another cause (an attempt, so removing
// it would hide the problem). Everything else is removed.
//
// With Generalize, observed sibling resources under one parent are merged into
// "parent:*", but only when each merged resource was actually used, an existing
// grant already covers the wildcard (the result is never broader than today),
// and the wildcard matches no call that was denied for lack of a grant. The
// wildcard still admits unobserved siblings inside that existing grant, which
// is why it is off by default and every merge is listed in Rewrites.
func SuggestShrink(a *UsageAnalysis, opts Options) Suggestion {
	minObs := max(1, opts.MinObservations)
	usedCount := make(map[string]int, len(a.Used))
	for _, u := range a.Used {
		usedCount[atomKey(u.Permission)] = u.Count
	}
	attempted := make(map[string]struct{}, len(a.AttemptedOnly))
	for _, p := range a.AttemptedOnly {
		attempted[atomKey(p)] = struct{}{}
	}

	var kept, removed []Permission
	observed := map[string]struct{}{}
	for _, g := range a.Grants {
		p := g.Permission
		k := atomKey(p)
		if usedCount[k] >= minObs {
			kept = append(kept, p)
			observed[k] = struct{}{}
		} else if _, ok := attempted[k]; ok {
			kept = append(kept, p)
		} else {
			removed = append(removed, p)
		}
	}

	var rewrites []Rewrite
	if opts.Generalize {
		kept, rewrites = generalize(a, kept, observed, opts)
	}
	return Suggestion{Keep: kept, Remove: removed, Rewrites: rewrites}
}

func generalize(a *UsageAnalysis, kept []Permission, observed map[string]struct{}, opts Options) ([]Permission, []Rewrite) {
	groupMin := opts.GeneralizeMin
	if groupMin == 0 {
		groupMin = defaultGeneralizeMin
	}
	groupMin = max(2, groupMin)

	var order []string
	groups := map[string]*group{}
	for i, p := range kept {
		if _, ok := observed[atomKey(p)]; !ok {
			continue
		}
		parent := parentOf(p.Resource)
		if parent == "" {
			continue
		}
		key := parent + "\x00" + p.Action + "\x00" + extrasKey(p)
		g, ok := groups[key]
		if !ok {
			g = &group{parent: parent, action: p.Action, extras: p}
			groups[key] = g
			order = append(order, key)
		}
		g.indexes = append(g.indexes, i)
	}

	granted := a.Granted()
	drop := map[int]struct{}{}
	replaceAt := map[int]Permission{}
	var rewrites []Rewrite
	for _, key := range order {
		g := groups[key]
		if len(g.indexes) < groupMin {
			continue
		}
		to := Permission{Action: g.action, Resource: g.parent + ":*", Conditions: slices.Clone(g.extras.Conditions)}
		if !slices.ContainsFunc(granted, func(gr Permission) bool { return Covers(gr, to) }) {
			continue
		}
		widensDenied := slices.ContainsFunc(a.DeniedNoGrant, func(d Pair) bool {
			return policy.Match(to.Action, d.Action) && policy.Match(to.Resource, d.Resource)
		})
		if widensDenied {
			continue
		}
		replaceAt[g.indexes[0]] = to
		from := make([]Permission, 0, len(g.indexes))
		for n, i := range g.indexes {
			if n > 0 {
				drop[i] = struct{}{}
			}
			from = append(from, kept[i])
		}
		rewrites = append(rewrites, Rewrite{From: from, To: to})
	}

	out := make([]Permission, 0, len(kept))
	for i, p := range kept {
		if _, ok := drop[i]; ok {
			continue
		}
		if r, ok := replaceAt[i]; ok {
			p = r
		}
		out = append(out, p)
	}
	return out, rewrites
}

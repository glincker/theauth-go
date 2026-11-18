package pathmatch

import "strings"

// Permission is a resource pattern and the actions it allows, the shape the delegation subset
// check compares. It mirrors the TypeScript Permission.
type Permission struct {
	Resource string
	Actions  []string
}

// PermissionSubset reports whether every child permission is covered by some parent permission
// (a child agent cannot hold more than its parent). The Go twin of the TypeScript
// isPermissionSubset(parent, child, mode). A parent action "*" covers any child action.
func PermissionSubset(mode Mode, parent, child []Permission) bool {
	for _, c := range child {
		if !covered(mode, parent, c) {
			return false
		}
	}
	return true
}

func covered(mode Mode, parent []Permission, c Permission) bool {
	for _, p := range parent {
		if !ResourceSubset(mode, p.Resource, c.Resource) {
			continue
		}
		ok := true
		for _, a := range c.Actions {
			if !hasAction(p.Actions, a) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func hasAction(actions []string, a string) bool {
	for _, x := range actions {
		if x == a || x == "*" {
			return true
		}
	}
	return false
}

// ResourceSubset reports whether child is the same as or more specific than parent. It is the
// runtime matcher applied to the child as a pattern, so a child never gets more than the parent
// could use itself, and a wildcard in the child is covered only by an equal or broader wildcard.
// A parent that is a shorter exact prefix of the child is NOT a superset (the pre fix TypeScript
// legacy test said yes there; see LegacyContains).
func ResourceSubset(mode Mode, parent, child string) bool {
	if parent == "*" || parent == child {
		return true
	}
	return Match(mode, parent, child)
}

// LegacyContains is the pre fix containment test: it also says yes when parent is a shorter
// exact prefix of child. It is only meant to decide which parent rule's constraints a child
// inherits (over matching there only adds constraints), never to grant anything.
func LegacyContains(parent, child string) bool {
	if parent == "*" || parent == child {
		return true
	}
	pp := strings.Split(parent, ":")
	cp := strings.Split(child, ":")
	for i, part := range pp {
		if part == "*" {
			return true
		}
		if i >= len(cp) || part != cp[i] {
			return false
		}
	}
	return len(pp) <= len(cp)
}

// ResourcesOverlap reports whether two resource patterns can select a common resource, so either
// may gate the other. It errs toward true.
func ResourcesOverlap(mode Mode, parent, child string) bool {
	if LegacyContains(parent, child) || LegacyContains(child, parent) {
		return true
	}
	return mode == Path && PathPatternsMayOverlap(parent, child)
}

func free(p string) bool { return p == "*" || p == "**" }

// segmentsMayOverlap asks whether two colon segments can select a common path.
func segmentsMayOverlap(x, y string) bool {
	if x == y {
		return true
	}
	if !strings.Contains(x, "/") && !strings.Contains(y, "/") {
		return false
	}
	px := strings.Split(x, "/")
	py := strings.Split(y, "/")
	i := 0
	for i < len(px) && i < len(py) && px[i] != "**" && py[i] != "**" {
		a, b := px[i], py[i]
		if !free(a) && !free(b) && a != b {
			return false
		}
		i++
	}
	open := contains(px, "**") || contains(py, "**")
	if !open {
		return len(px) == len(py)
	}
	for j := 1; j <= len(px)-i && j <= len(py)-i; j++ {
		a, b := px[len(px)-j], py[len(py)-j]
		if a == "**" || b == "**" {
			break
		}
		if !free(a) && !free(b) && a != b {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// PathPatternsMayOverlap could the two patterns select a common resource under path matching.
// It over approximates, so it is safe for deciding which parent rule constraints apply to a child.
func PathPatternsMayOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	pa := strings.Split(a, ":")
	pb := strings.Split(b, ":")
	n := max(len(pa), len(pb))
	for i := 0; i < n; i++ {
		if i >= len(pa) || i >= len(pb) {
			// A missing segment on one side: TS checks the wildcard on the present side first.
			var present string
			if i < len(pa) {
				present = pa[i]
			} else {
				present = pb[i]
			}
			return free(present)
		}
		x, y := pa[i], pb[i]
		if free(x) || free(y) {
			return true
		}
		if !segmentsMayOverlap(x, y) {
			return false
		}
	}
	return true
}

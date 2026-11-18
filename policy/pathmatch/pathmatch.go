// Package pathmatch is resource pattern matching in two modes, the Go twin of the TypeScript
// core matcher (packages/core/src/policy/resource-match.ts). testdata/vectors.json is generated
// from the TS code (docs-local/vectors/gen-pathmatch-vectors.mjs) and replayed by the tests.
//
// Colon (the default): resources are ":" separated. A pattern segment that is exactly "*" matches
// that segment and everything after it. Nothing else is a wildcard, so "ros2:/fleet/*" is literal
// text.
//
// Path (opt in): the colon rules still apply, and inside one colon segment "/" separates path
// segments. A path segment that is exactly "*" matches one segment, "**" matches one or more.
// Wildcards never match an empty, "." or ".." segment (so "/fleet/a/../../admin" cannot ride a
// glob), never cross a ":", and a partial glob such as "r*" is literal. A whole colon segment "*"
// or "**" as the LAST pattern segment matches the rest. Before the last segment it matches
// exactly one non-empty segment. There are no MQTT "+" or "#" aliases. Matching is case
// sensitive and nothing is percent decoded.
//
// The package imports only the standard library, so the device side (iot/device) can use it.
package pathmatch

import "strings"

// Mode selects the matcher.
type Mode string

const (
	// Colon is the default matcher.
	Colon Mode = "colon"
	// Path is the opt in path aware matcher.
	Path Mode = "path"
)

// Resolve reads an untrusted mode value. Anything but the exact string "path" is Colon.
func Resolve(v string) Mode {
	if v == string(Path) {
		return Path
	}
	return Colon
}

// Match applies the matcher for mode. An unknown mode is Colon.
func Match(mode Mode, pattern, resource string) bool {
	if mode == Path {
		return MatchPath(pattern, resource)
	}
	return MatchColon(pattern, resource)
}

// cut splits off the first segment at sep. more reports whether sep followed it, that is whether
// rest holds further segments (possibly one empty segment). Walking a resource this way avoids
// the slice strings.Split would allocate on every match.
func cut(s string, sep byte) (seg, rest string, more bool) {
	if i := strings.IndexByte(s, sep); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// MatchColon is the default matcher: colon segments, a "*" segment matches the rest, a lone "*"
// matches everything.
func MatchColon(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	rp, rrest, rmore := cut(resource, ':')
	haveR := true
	for {
		part, prest, pmore := cut(pattern, ':')
		if part == "*" {
			return true
		}
		if !haveR || part != rp {
			return false
		}
		if !pmore {
			return !rmore
		}
		pattern = prest
		if rmore {
			rp, rrest, rmore = cut(rrest, ':')
		} else {
			haveR = false
		}
	}
}

// MatchPath is the path aware matcher.
func MatchPath(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	actual, rrest, rmore := cut(resource, ':')
	haveR := true
	for {
		part, prest, pmore := cut(pattern, ':')
		wild := part == "*" || part == "**"
		if wild && !pmore {
			return true
		}
		if !haveR {
			return false
		}
		switch {
		case wild:
			// Before the last segment a whole segment wildcard is one non-empty segment.
			if actual == "" || actual == "**" {
				return false
			}
		case part == actual:
		case !strings.Contains(part, "/") || !strings.Contains(actual, "/"):
			return false
		case !matchParts(part, actual):
			return false
		}
		if !pmore {
			return !rmore
		}
		pattern = prest
		if rmore {
			actual, rrest, rmore = cut(rrest, ':')
		} else {
			haveR = false
		}
	}
}

// plain reports whether a wildcard may stand for the path segment.
func plain(seg string) bool { return seg != "" && seg != "." && seg != ".." }

// maxStackParts is how many "/" parts of one colon segment matchParts handles without a heap
// allocation. A longer segment still works, it just allocates.
const maxStackParts = 32

// splitParts splits s at "/" into buf, growing it only past maxStackParts.
func splitParts(buf []string, s string) []string {
	for {
		seg, rest, more := cut(s, '/')
		buf = append(buf, seg)
		if !more {
			return buf
		}
		s = rest
	}
}

// matchParts matches the "/" separated parts of one colon segment. below[j] is "pattern[i+1:]
// matches resource[j:]" and row[j] the same for pattern[i:].
func matchParts(patternSeg, resourceSeg string) bool {
	var pbuf, rbuf [maxStackParts]string
	pattern := splitParts(pbuf[:0], patternSeg)
	resource := splitParts(rbuf[:0], resourceSeg)
	m, n := len(pattern), len(resource)
	var abuf, bbuf [maxStackParts + 1]bool
	var below, row []bool
	if n+1 > len(abuf) {
		below, row = make([]bool, n+1), make([]bool, n+1)
	} else {
		below, row = abuf[:n+1], bbuf[:n+1]
	}
	below[n] = true
	for i := m - 1; i >= 0; i-- {
		p := pattern[i]
		row[n] = false
		for j := n - 1; j >= 0; j-- {
			r := resource[j]
			switch p {
			case "**":
				// One segment here, then stop or keep consuming. A requested "*" or "**" is
				// consumed as written: it is a pattern being compared, not a concrete name.
				row[j] = plain(r) && (below[j+1] || row[j+1])
			case "*":
				row[j] = r != "**" && plain(r) && below[j+1]
			default:
				row[j] = p == r && below[j+1]
			}
		}
		below, row = row, below
	}
	return below[0]
}

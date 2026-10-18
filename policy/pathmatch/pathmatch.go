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

// MatchColon is the default matcher: colon segments, a "*" segment matches the rest, a lone "*"
// matches everything.
func MatchColon(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	pp := strings.Split(pattern, ":")
	rp := strings.Split(resource, ":")
	for i, part := range pp {
		if part == "*" {
			return true
		}
		if i >= len(rp) || part != rp[i] {
			return false
		}
	}
	return len(pp) == len(rp)
}

// MatchPath is the path aware matcher.
func MatchPath(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	pp := strings.Split(pattern, ":")
	rp := strings.Split(resource, ":")
	for i, part := range pp {
		wild := part == "*" || part == "**"
		if wild && i == len(pp)-1 {
			return true
		}
		if i >= len(rp) {
			return false
		}
		actual := rp[i]
		if wild {
			// Before the last segment a whole segment wildcard is one non-empty segment.
			if actual == "" || actual == "**" {
				return false
			}
			continue
		}
		if part == actual {
			continue
		}
		if !strings.Contains(part, "/") || !strings.Contains(actual, "/") {
			return false
		}
		if !matchParts(strings.Split(part, "/"), strings.Split(actual, "/")) {
			return false
		}
	}
	return len(pp) == len(rp)
}

// plain reports whether a wildcard may stand for the path segment.
func plain(seg string) bool { return seg != "" && seg != "." && seg != ".." }

// matchParts matches the "/" separated parts of one colon segment. below[j] is "pattern[i+1:]
// matches resource[j:]" and row[j] the same for pattern[i:].
func matchParts(pattern, resource []string) bool {
	m, n := len(pattern), len(resource)
	below := make([]bool, n+1)
	row := make([]bool, n+1)
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

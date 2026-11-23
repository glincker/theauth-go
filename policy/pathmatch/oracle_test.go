package pathmatch

import (
	"strings"
	"testing"
)

// The matchers below are the original strings.Split implementations. They stay as an oracle for
// the allocation free versions in pathmatch.go, which must agree on every input.

func oracleColon(pattern, resource string) bool {
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

func oraclePath(pattern, resource string) bool {
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
		if !oracleParts(strings.Split(part, "/"), strings.Split(actual, "/")) {
			return false
		}
	}
	return len(pp) == len(rp)
}

func oracleParts(pattern, resource []string) bool {
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

func resourceCorpus() []string {
	segs := []string{"", "a", "*", "**", "/a", "/a/*", "/a/**", "/a/../b", "a/b/c", "r*"}
	out := []string{""}
	var rec func(prefix []string, depth int)
	rec = func(prefix []string, depth int) {
		if len(prefix) > 0 {
			out = append(out, strings.Join(prefix, ":"))
		}
		if depth == 3 {
			return
		}
		for _, s := range segs {
			rec(append(append([]string(nil), prefix...), s), depth+1)
		}
	}
	rec(nil, 0)
	// A segment with more parts than the stack buffers hold.
	long := strings.Repeat("a/", maxStackParts+8) + "z"
	longStar := strings.Repeat("*/", maxStackParts+8) + "z"
	return append(out, long, longStar, "x:"+long, "x:"+longStar, "/"+strings.Repeat("**/", 40))
}

func TestMatchersEqualOracle(t *testing.T) {
	corpus := resourceCorpus()
	n := 0
	for _, p := range corpus {
		for _, r := range corpus {
			if got, want := MatchColon(p, r), oracleColon(p, r); got != want {
				t.Fatalf("MatchColon(%q, %q) = %v, oracle %v", p, r, got, want)
			}
			if got, want := MatchPath(p, r), oraclePath(p, r); got != want {
				t.Fatalf("MatchPath(%q, %q) = %v, oracle %v", p, r, got, want)
			}
			n++
		}
	}
	t.Logf("compared %d pairs", n)
}

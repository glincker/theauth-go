package policy

import "strings"

func token(p string, i int) (c byte, width int, star bool) {
	switch {
	case p[i] == '*':
		return 0, 1, true
	case p[i] == '\\' && i+1 < len(p):
		return p[i+1], 2, false
	default:
		return p[i], 1, false
	}
}

// Match reports whether s matches pattern, where * matches any run of bytes
// (including none and including "/") and a backslash escapes the next byte.
// Matching is case sensitive, iterative and O(len(pattern)*len(s)).
func Match(pattern, s string) bool {
	p, i := 0, 0
	starP, starI := -1, 0
	for i < len(s) {
		if p < len(pattern) {
			c, w, star := token(pattern, p)
			if star {
				starP, starI = p, i
				p += w
				continue
			}
			if c == s[i] {
				p += w
				i++
				continue
			}
		}
		if starP < 0 {
			return false
		}
		starI++
		i = starI
		p = starP + 1
	}
	for p < len(pattern) {
		_, w, star := token(pattern, p)
		if !star {
			return false
		}
		p += w
	}
	return true
}

// Escape makes v match itself literally when used inside a pattern.
func Escape(v string) string {
	if !strings.ContainsAny(v, `*\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '*' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func isVarChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// expand replaces {name} with the value (glob-escaped when escape is set) of vars[name]. Text in braces
// that is not a valid variable name stays literal. ok is false when a
// referenced variable is missing.
func expand(s string, vars map[string]string, escape bool) (out string, ok bool) {
	if !strings.Contains(s, "{") {
		return s, true
	}
	var b strings.Builder
	ok = true
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			b.WriteByte(s[i])
			continue
		}
		j := i + 1
		for j < len(s) && isVarChar(s[j]) {
			j++
		}
		if j == i+1 || j >= len(s) || s[j] != '}' {
			b.WriteByte(s[i])
			continue
		}
		v, found := vars[s[i+1:j]]
		if !found {
			ok = false
		}
		if escape {
			v = Escape(v)
		}
		b.WriteString(v)
		i = j
	}
	return b.String(), ok
}

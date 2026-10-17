package as

// claims.go: required claim matchers for TrustedJWTIssuer. After the
// signature of a jwt-bearer assertion is verified, every matcher on the
// issuer must pass before the assertion is exchanged. Matching is exact,
// case sensitive and never coerces types: a claim that is not a string (or an
// array of strings) can only satisfy Present.

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidClaimMatcher is returned (wrapped) when a ClaimMatcher is
// misconfigured. It surfaces from theauth.New.
var ErrInvalidClaimMatcher = errors.New("theauth: invalid claim matcher")

// ClaimMatcher requires one claim of a verified assertion to satisfy exactly
// one operator.
//
// Claim is a top level claim name. A name with dots that is not itself a
// top level key is read as a nested path through JSON objects ("a.b.c").
// Equals, OneOf and Pattern compare against string claims; when the claim is
// an array, the matcher passes if any string element satisfies it. Numbers,
// booleans, objects and null never match those operators.
//
// Exactly one operator must be set:
//   - Equals: the value is exactly this non-empty string.
//   - OneOf: the value is exactly one of these non-empty strings.
//   - Pattern: the value matches this glob. "*" matches any run of
//     characters (including "/" and the empty run) and is the only special
//     character. The whole value must match (anchored), there is no regex.
//   - Present: the claim exists and is not null, "" or an empty array.
type ClaimMatcher struct {
	Claim   string
	Equals  string
	OneOf   []string
	Pattern string
	Present bool
}

// Validate reports a misconfigured matcher with a descriptive error.
func (m ClaimMatcher) Validate() error {
	if m.Claim == "" {
		return fmt.Errorf("%w: claim name is empty", ErrInvalidClaimMatcher)
	}
	if strings.HasPrefix(m.Claim, ".") || strings.HasSuffix(m.Claim, ".") || strings.Contains(m.Claim, "..") {
		return fmt.Errorf("%w: claim %q is not a valid path", ErrInvalidClaimMatcher, m.Claim)
	}
	ops := 0
	if m.Equals != "" {
		ops++
	}
	if len(m.OneOf) > 0 {
		ops++
	}
	if m.Pattern != "" {
		ops++
	}
	if m.Present {
		ops++
	}
	switch {
	case ops == 0:
		return fmt.Errorf("%w: claim %q needs one of Equals, OneOf, Pattern or Present", ErrInvalidClaimMatcher, m.Claim)
	case ops > 1:
		return fmt.Errorf("%w: claim %q sets more than one operator", ErrInvalidClaimMatcher, m.Claim)
	}
	for _, v := range m.OneOf {
		if v == "" {
			return fmt.Errorf("%w: claim %q OneOf contains an empty string", ErrInvalidClaimMatcher, m.Claim)
		}
	}
	return nil
}

// matches reports whether claims satisfies the matcher. A missing claim
// fails closed.
func (m ClaimMatcher) matches(claims map[string]any) bool {
	v, ok := lookupClaim(claims, m.Claim)
	if !ok || v == nil {
		return false
	}
	if m.Present {
		switch t := v.(type) {
		case string:
			return t != ""
		case []any:
			return len(t) > 0
		}
		return true
	}
	switch t := v.(type) {
	case string:
		return m.matchString(t)
	case []any:
		for _, e := range t {
			if s, isStr := e.(string); isStr && m.matchString(s) {
				return true
			}
		}
	}
	return false
}

func (m ClaimMatcher) matchString(s string) bool {
	switch {
	case m.Equals != "":
		return s == m.Equals
	case len(m.OneOf) > 0:
		return jwtStringIn(s, m.OneOf)
	case m.Pattern != "":
		return globMatch(m.Pattern, s)
	}
	return false
}

// lookupClaim finds a top level key first, then walks a dotted path.
func lookupClaim(claims map[string]any, name string) (any, bool) {
	if v, ok := claims[name]; ok {
		return v, true
	}
	if !strings.Contains(name, ".") {
		return nil, false
	}
	var cur any = claims
	for _, part := range strings.Split(name, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// globMatch is an anchored glob where "*" matches any run of characters and
// every other character matches itself. Iterative with single-star
// backtracking, so it runs in O(len(pattern)*len(s)) at worst.
func globMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			mark++
			i, p = mark, star+1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// failedClaims returns the names of the matchers that did not pass, in
// configuration order and without duplicates. Every matcher is evaluated so
// the audit event names all of them. Values are never returned.
func failedClaims(matchers []ClaimMatcher, claims map[string]any) []string {
	var failed []string
	for _, m := range matchers {
		if !m.matches(claims) && !jwtStringIn(m.Claim, failed) {
			failed = append(failed, m.Claim)
		}
	}
	return failed
}

func validateClaimMatchers(issuer string, matchers []ClaimMatcher) error {
	for i, m := range matchers {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("trusted jwt issuer %q required claim %d: %w", issuer, i, err)
		}
	}
	return nil
}

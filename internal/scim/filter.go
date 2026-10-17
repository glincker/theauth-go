// Package scim holds the SCIM parsing helpers the root package uses internally. The equality-only filter
// parser is kept here so it can be tested without the root package surface.
package scim

import (
	"errors"
	"strings"
)

// ErrUnsupportedFilter is returned by ParseEqFilter when the input does
// not match the supported "<attrPath> eq <quoted-value>" shape. Callers
// in the root theauth package translate this to the package-level
// theauth.ErrUnsupportedFilter sentinel that consumers can errors.Is
// against.
var ErrUnsupportedFilter = errors.New("scim: filter not supported")

// ParseEqFilter reads `<attrPath> eq <quoted-value>` and returns the
// attribute path and the unquoted value.
//
// Accepted shape, with whitespace collapsed and the value double-quoted:
//
//	userName eq "alice@x"
//
// Any other operator (pr, co, sw, ne, and, or) or any other shape returns
// ErrUnsupportedFilter so the SCIM handler can emit RFC 7644 400
// invalidFilter. Empty input returns ("", "", nil); the caller treats an
// empty filter as "list everything" per RFC 7644 section 3.4.2.
func ParseEqFilter(s string) (field, value string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", nil
	}
	// Split into three pieces: attrPath, "eq", quoted value. We do this by
	// index lookup rather than strings.Fields so the quoted value can keep
	// any internal whitespace.
	parts := strings.SplitN(s, " ", 3)
	if len(parts) != 3 {
		return "", "", ErrUnsupportedFilter
	}
	field = parts[0]
	op := strings.ToLower(parts[1])
	rest := strings.TrimSpace(parts[2])
	if op != "eq" {
		return "", "", ErrUnsupportedFilter
	}
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", ErrUnsupportedFilter
	}
	value = rest[1 : len(rest)-1]
	if strings.ContainsAny(field, `"' (){}[]`) {
		return "", "", ErrUnsupportedFilter
	}
	return field, value, nil
}

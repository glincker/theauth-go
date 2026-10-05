// Package pathprefix holds the route prefix default and validation shared by
// the root package and the internal service packages.
package pathprefix

import (
	"errors"
	"strings"
)

// Default is the route prefix used when none is configured.
const Default = "/auth"

// Normalize returns p, or Default when p is empty.
func Normalize(p string) string {
	if p == "" {
		return Default
	}
	return p
}

// Validate checks that p starts with a slash, has no trailing slash and
// carries no query, fragment, whitespace or empty/dot segments.
func Validate(p string) error {
	if p == "" {
		return nil
	}
	if p[0] != '/' {
		return errors.New("must start with '/'")
	}
	if p == "/" || strings.HasSuffix(p, "/") {
		return errors.New("must not end with '/'")
	}
	if strings.ContainsAny(p, "?#{}* \t\r\n\\") {
		return errors.New("must not contain a query, fragment, wildcard, whitespace or backslash")
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("must not contain empty or dot segments")
		}
	}
	return nil
}

package spiffe

import (
	"errors"
	"strings"
)

// MaxIDBytes is the longest SPIFFE ID an implementation must accept (SPIFFE-ID.md section 2.3).
const MaxIDBytes = 2048

const idPrefix = "spiffe://"

// ID is a parsed SPIFFE ID.
type ID struct {
	// String is the whole id, for example spiffe://example.org/ns/prod/sa/robot.
	String      string
	TrustDomain string
	// Path is empty for a trust domain id, else it starts with "/".
	Path string
}

// ParseID parses a SPIFFE ID per SPIFFE-ID.md section 2: scheme spiffe, a lowercase trust domain of
// [a-z0-9._-], an optional path of non empty segments of [A-Za-z0-9._-] (no "." or ".." segment, no
// trailing slash), no userinfo, port, query, fragment or percent encoding, at most 2048 bytes. An
// upper case scheme or host is refused instead of folded, so one workload never has two spellings.
func ParseID(s string) (ID, error) {
	if len(s) > MaxIDBytes {
		return ID{}, errors.New("SPIFFE ID is too long")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return ID{}, errors.New("SPIFFE ID has a non printable or non ASCII character")
		}
	}
	rest, ok := strings.CutPrefix(s, idPrefix)
	if !ok {
		return ID{}, errors.New(`SPIFFE ID scheme must be lowercase "spiffe"`)
	}
	if strings.ContainsAny(rest, "?#") {
		return ID{}, errors.New("SPIFFE ID must not have a query or fragment")
	}
	td, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		td, path = rest[:i], rest[i:]
	}
	if td == "" {
		return ID{}, errors.New("SPIFFE ID has an empty trust domain")
	}
	if len(td) > 255 {
		return ID{}, errors.New("trust domain is too long")
	}
	if strings.ContainsAny(td, "@:%") {
		return ID{}, errors.New("trust domain must not have userinfo, a port or percent encoding")
	}
	for i := 0; i < len(td); i++ {
		if !isTrustDomainChar(td[i]) {
			return ID{}, errors.New("trust domain may only contain lowercase letters, digits, dots, dashes and underscores")
		}
	}
	if path != "" {
		for _, seg := range strings.Split(path[1:], "/") {
			switch seg {
			case "":
				return ID{}, errors.New("SPIFFE ID path has an empty segment")
			case ".", "..":
				return ID{}, errors.New("SPIFFE ID path has a dot segment")
			}
			for i := 0; i < len(seg); i++ {
				if !isSegmentChar(seg[i]) {
					return ID{}, errors.New("SPIFFE ID path has a character outside [A-Za-z0-9._-]")
				}
			}
		}
	}
	return ID{String: s, TrustDomain: td, Path: path}, nil
}

// ParseTrustDomain accepts example.org or spiffe://example.org.
func ParseTrustDomain(s string) (string, bool) {
	if !strings.HasPrefix(s, idPrefix) {
		s = idPrefix + s
	}
	id, err := ParseID(s)
	if err != nil || id.Path != "" {
		return "", false
	}
	return id.TrustDomain, true
}

func isTrustDomainChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

func isSegmentChar(c byte) bool {
	return isTrustDomainChar(c) || c >= 'A' && c <= 'Z'
}

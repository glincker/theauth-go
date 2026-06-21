package theauth

import (
	"errors"
	"strings"
)

// parseSCIMUserFilter accepts the equality-only filter subset documented
// in v0.7 §6.4 and returns a SCIMUserFilter. Any other shape returns
// ErrUnsupportedFilter so the handler can emit 400 invalidFilter.
//
// Accepted forms:
//
//	userName eq "alice@x"
//	externalId eq "okta-123"
//	emails.value eq "alice@x"
//
// Whitespace is collapsed; the value is unquoted. We do not implement
// pr / co / sw / ne / and / or. Okta and Azure AD only ever issue eq
// against this whitelist on the User list endpoint.
func parseSCIMUserFilter(s string) (SCIMUserFilter, error) {
	var out SCIMUserFilter
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	field, value, err := parseEqFilter(s)
	if err != nil {
		return out, err
	}
	switch field {
	case "userName":
		out.UserName = value
	case "externalId":
		out.ExternalID = value
	case "emails.value":
		out.Email = value
	default:
		return out, ErrUnsupportedFilter
	}
	return out, nil
}

// parseSCIMGroupFilter accepts the equality-only filter subset for groups.
//
//	displayName eq "Admins"
//	externalId  eq "okta-grp-1"
func parseSCIMGroupFilter(s string) (SCIMGroupFilter, error) {
	var out SCIMGroupFilter
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	field, value, err := parseEqFilter(s)
	if err != nil {
		return out, err
	}
	switch field {
	case "displayName":
		out.DisplayName = value
	case "externalId":
		out.ExternalID = value
	default:
		return out, ErrUnsupportedFilter
	}
	return out, nil
}

// parseEqFilter reads "<attrPath> eq <quoted-value>" and returns the parts.
// Returns ErrUnsupportedFilter if the input does not match this shape.
func parseEqFilter(s string) (string, string, error) {
	// Collapse multiple spaces. SCIM allows them; we accept tabs too.
	s = strings.TrimSpace(s)
	// Split into three pieces: attrPath, "eq", quoted value.
	// We deliberately do this by index lookup instead of strings.Fields so
	// the quoted value can keep its internal whitespace.
	parts := strings.SplitN(s, " ", 3)
	if len(parts) != 3 {
		return "", "", ErrUnsupportedFilter
	}
	field := parts[0]
	op := strings.ToLower(parts[1])
	rest := strings.TrimSpace(parts[2])
	if op != "eq" {
		return "", "", ErrUnsupportedFilter
	}
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", ErrUnsupportedFilter
	}
	value := rest[1 : len(rest)-1]
	if strings.ContainsAny(field, `"' (){}[]`) {
		return "", "", ErrUnsupportedFilter
	}
	return field, value, nil
}

// Ensure errors.Is still works for callers (silences unused-import on the
// off-chance that a future refactor moves the only direct errors usage
// out of this file).
var _ = errors.New

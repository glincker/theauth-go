package internal

import (
	"fmt"
	"strings"
)

// ValidationResult collects errors and warnings from a bundle validation pass.
type ValidationResult struct {
	Errors   []string
	Warnings []string
}

// OK returns true when there are no validation errors (warnings are allowed).
func (v *ValidationResult) OK() bool { return len(v.Errors) == 0 }

// ValidateBundle performs structural and semantic checks on b.
// It does not touch storage; call this before --apply or as the sole action
// for the "validate" sub-command.
func ValidateBundle(b *Bundle) ValidationResult {
	var r ValidationResult

	if b.SchemaVersion != SchemaVersion {
		r.Errors = append(r.Errors, fmt.Sprintf(
			"unsupported schema_version %q (expected %q)", b.SchemaVersion, SchemaVersion,
		))
	}

	if b.Source == "" {
		r.Errors = append(r.Errors, "bundle.source is empty")
	}

	// Check for duplicate source IDs in users.
	seenIDs := make(map[string]int)
	for i, u := range b.Users {
		if u.SourceID == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("users[%d]: source_id is empty", i))
		}
		if u.Email == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("users[%d] (%s): email is empty", i, u.SourceID))
		}
		seenIDs[u.SourceID]++
	}
	for id, count := range seenIDs {
		if count > 1 {
			r.Errors = append(r.Errors, fmt.Sprintf("duplicate source_id %q (%d occurrences)", id, count))
		}
	}

	// Check for duplicate emails (case-insensitive).
	seenEmails := make(map[string]string)
	for _, u := range b.Users {
		lc := strings.ToLower(u.Email)
		if prev, ok := seenEmails[lc]; ok {
			r.Errors = append(r.Errors, fmt.Sprintf(
				"duplicate email %q: source_ids %q and %q", lc, prev, u.SourceID,
			))
		} else {
			seenEmails[lc] = u.SourceID
		}
	}

	// Cross-reference oauth_accounts to users.
	validIDs := make(map[string]bool, len(b.Users))
	for _, u := range b.Users {
		validIDs[u.SourceID] = true
	}
	for i, a := range b.OAuthAccounts {
		if !validIDs[a.SourceUserID] {
			r.Warnings = append(r.Warnings, fmt.Sprintf(
				"oauth_accounts[%d]: source_user_id %q not found in users; row will be skipped",
				i, a.SourceUserID,
			))
		}
		if a.Provider == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("oauth_accounts[%d]: provider is empty", i))
		}
		if a.ProviderUserID == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("oauth_accounts[%d]: provider_user_id is empty", i))
		}
	}

	// Cross-reference passwords.
	for i, p := range b.Passwords {
		if !validIDs[p.SourceUserID] {
			r.Warnings = append(r.Warnings, fmt.Sprintf(
				"passwords[%d]: source_user_id %q not found in users; row will be skipped",
				i, p.SourceUserID,
			))
		}
	}

	return r
}

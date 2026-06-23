package audit_test

import (
	"testing"

	theauth "github.com/glincker/theauth-go"
)

// TestAuditRedactorAllocPerOp verifies that key matching is case-insensitive
// whether the key is lowercase, uppercase, or mixed-case. This behavior test
// guards the EqualFold refactor (perf re-audit 2026-06-21, item 4): if the
// key set were accidentally compared with an exact match instead of
// EqualFold, uppercase variants would slip through unredacted.
func TestAuditRedactorAllocPerOp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key  string
		desc string
	}{
		{"password", "lowercase"},
		{"Password", "mixed-case title"},
		{"PASSWORD", "uppercase"},
		{"secret", "lowercase secret"},
		{"Secret", "mixed-case secret"},
		{"token", "lowercase token"},
		{"TOKEN", "uppercase token"},
		{"refresh_token", "lowercase refresh_token"},
		{"REFRESH_TOKEN", "uppercase refresh_token"},
		{"access_token", "lowercase access_token"},
		{"ACCESS_TOKEN", "uppercase access_token"},
		{"code", "lowercase code"},
		{"CODE", "uppercase code"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.desc, func(t *testing.T) {
			t.Parallel()
			in := map[string]any{c.key: "super-secret-value"}
			out := theauth.DefaultRedactor(in)
			if out[c.key] != "[REDACTED]" {
				t.Errorf("key %q (%s): expected [REDACTED], got %v", c.key, c.desc, out[c.key])
			}
		})
	}
}

// TestAuditRedactorSafeKeysUnchanged confirms that non-secret keys are never
// redacted regardless of their casing.
func TestAuditRedactorSafeKeysUnchanged(t *testing.T) {
	t.Parallel()

	in := map[string]any{
		"email":     "user@example.com",
		"userId":    "ulid123",
		"action":    "login",
		"ipAddress": "1.2.3.4",
		"userAgent": "Go-http-client/1.1",
	}
	out := theauth.DefaultRedactor(in)
	for k, want := range in {
		if got := out[k]; got != want {
			t.Errorf("safe key %q: got %v, want %v", k, got, want)
		}
	}
}

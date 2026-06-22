package theauth_test

import (
	"testing"

	"github.com/glincker/theauth-go"
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
		{"Code", "mixed-case code"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			metadata := map[string]any{tc.key: "super-secret-value"}
			out := theauth.DefaultRedactor(metadata)
			got, ok := out[tc.key]
			if !ok {
				t.Fatalf("key %q absent from redacted output", tc.key)
			}
			if got != "[REDACTED]" {
				t.Errorf("key %q (%s): got %q, want [REDACTED]", tc.key, tc.desc, got)
			}
		})
	}
}

// TestAuditRedactorNonSecretKeyPassesThrough confirms that non-secret keys
// are not altered by the redactor, ensuring the EqualFold change does not
// accidentally over-redact.
func TestAuditRedactorNonSecretKeyPassesThrough(t *testing.T) {
	t.Parallel()
	metadata := map[string]any{
		"user_id":  "01HXY...",
		"action":   "login",
		"password": "must-be-redacted",
	}
	out := theauth.DefaultRedactor(metadata)
	if out["user_id"] != "01HXY..." {
		t.Errorf("user_id should pass through unmodified, got %v", out["user_id"])
	}
	if out["action"] != "login" {
		t.Errorf("action should pass through unmodified, got %v", out["action"])
	}
	if out["password"] != "[REDACTED]" {
		t.Errorf("password must be redacted, got %v", out["password"])
	}
}

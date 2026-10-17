package bench

import (
	"testing"

	"github.com/glincker/theauth-go/v2"
)

// BenchmarkAuditRedactor measures DefaultRedactor on a payload shaped like a successful token
// grant. It catches regressions to the per-key ToLower allocation that EqualFold removed.
func BenchmarkAuditRedactor(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := map[string]any{
			"grant_type":    "refresh_token",
			"scope":         "files.read",
			"resource":      "https://files.example.com/mcp",
			"refresh_token": "tok_very_secret_value",
			"access_token":  "at_very_secret_value",
			"grants": map[string]any{
				"refresh_token": "nested_secret",
				"client_id":     "client-bench",
			},
		}
		_ = theauth.DefaultRedactor(m)
	}
}

package bench

import (
	"testing"

	"github.com/glincker/theauth-go"
)

// BenchmarkAuditRedactor measures DefaultRedactor on a representative
// metadata map: three secret keys at top level plus one nested map. This
// mirrors the payload emitted on a successful token grant (grant_type,
// scope, resource at top level; refresh_token inside a nested "grants"
// map). The EqualFold refactor (perf re-audit 2026-06-21 item 4) removed
// the per-key ToLower heap allocation; this benchmark catches any
// regression to the old path.
//
// gate:include
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

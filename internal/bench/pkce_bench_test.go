package bench

import (
	"testing"

	"github.com/glincker/theauth-go/v2/crypto"
)

// BenchmarkPKCEChallenge measures NewCodeVerifier and CodeChallenge together, which run on every
// authorize flow.
func BenchmarkPKCEChallenge(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v, err := crypto.NewCodeVerifier()
		if err != nil {
			b.Fatal(err)
		}
		_ = crypto.CodeChallenge(v)
	}
}

package bench

import (
	"testing"

	"github.com/glincker/theauth-go/crypto"
)

// BenchmarkPKCEChallenge measures NewCodeVerifier + CodeChallenge as a
// pair: one runs on every OAuth start, the other on every authorize URL
// build.
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

package crypto

import "testing"

// BenchmarkArgon2Hash measures a single HashPassword call at the production
// parameters (m=65536, t=3, p=4). The cost is intentionally high per OWASP
// 2026; this benchmark exists to catch accidental work-factor increases that
// would DoS the login endpoint, not to optimise the operation away.
//
// gate:include
func BenchmarkArgon2Hash(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashPassword("correct-horse-battery-staple")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkArgon2Verify measures VerifyPassword at production parameters.
// A regression here means either the work factor was increased (catch in
// review) or a new code path added unnecessary copies of the key material.
//
// gate:include
func BenchmarkArgon2Verify(b *testing.B) {
	phc, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyPassword("correct-horse-battery-staple", phc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

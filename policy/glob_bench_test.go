package policy

import "testing"

func benchMatch(b *testing.B, pattern, s string, want bool) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Match(pattern, s) != want {
			b.Fatal("unexpected result")
		}
	}
}

func BenchmarkMatchExact(b *testing.B) { benchMatch(b, "files.read", "files.read", true) }
func BenchmarkMatchPrefixStar(b *testing.B) {
	benchMatch(b, "project/*", "project/p1/env/staging/deploy", true)
}
func BenchmarkMatchMiddleStar(b *testing.B) {
	benchMatch(b, "project/*/env/prod", "project/p1/env/prod", true)
}
func BenchmarkMatchMiss(b *testing.B) {
	benchMatch(b, "project/*/env/prod", "project/p1/env/staging", false)
}
func BenchmarkMatchManyStars(b *testing.B) {
	benchMatch(b, "*a*b*c*d*", "xxaxxbxxcxxdxx", true)
}

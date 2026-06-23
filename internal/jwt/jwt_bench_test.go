package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/jwt"
)

// BenchmarkJWTSign measures a single Ed25519 JWT sign (header + payload
// marshal + base64url + ed25519.Sign). Catches accidental algorithm changes
// or extra allocations in the signing path.
//
// gate:include
func BenchmarkJWTSign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	claims := jwt.Claims{
		Iss:      "https://auth.example.com",
		Sub:      "user-bench-001",
		Aud:      "https://files.example.com/mcp",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      "jti-bench-001",
		ClientID: "client-bench",
		Scope:    "files.read",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwt.Sign(claims, "kid-bench", priv)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJWTVerify measures a single Ed25519 JWT verify (split + base64url
// decode + ed25519.Verify + claims unmarshal). Catches algorithm confusion
// regressions and extra allocation in the verify path.
//
// gate:include
func BenchmarkJWTVerify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	claims := jwt.Claims{
		Iss:      "https://auth.example.com",
		Sub:      "user-bench-001",
		Aud:      "https://files.example.com/mcp",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      "jti-bench-001",
		ClientID: "client-bench",
		Scope:    "files.read",
	}
	token, err := jwt.Sign(claims, "kid-bench", priv)
	if err != nil {
		b.Fatal(err)
	}
	resolve := func(kid string) (ed25519.PublicKey, bool) {
		if kid == "kid-bench" {
			return pub, true
		}
		return nil, false
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwt.Verify(token, resolve, "https://files.example.com/mcp", time.Now())
		if err != nil {
			b.Fatal(err)
		}
	}
}

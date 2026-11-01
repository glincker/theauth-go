package dpop_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
)

func FuzzParseProofAndVerify(f *testing.F) {
	// Fixed clock and key: the fuzz workers run in separate processes and must build the same proof.
	now := time.Unix(1_800_000_000, 0).UTC()
	valid := deterministicProof(now)
	for _, s := range []string{"", ".", "..", "a.b.c", valid, valid + ".x", strings.Repeat("A", 1<<16), "e30.e30.e30", "\x00.\x00.\x00", "eyJhbGciOiJub25lIn0.e30.", "ÿ.ÿ.ÿ"} {
		f.Add(s)
	}
	svc, err := dpop.New(dpop.Config{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if _, _, _, _, err := dpop.ParseProof(token); err != nil && !errors.Is(err, dpop.ErrMalformedProof) {
			t.Fatalf("parse error must wrap ErrMalformedProof: %v", err)
		}
		// Mutated proofs must never verify unless they are byte-identical to the signed one.
		if _, err := svc.Verify(token, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err == nil && token != valid {
			t.Fatalf("mutated proof verified: %q", token)
		}
	})
}

func deterministicProof(now time.Time) string {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	jwk := &dpop.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}
	hdr, _ := json.Marshal(dpop.ProofHeader{Typ: dpop.ProofTyp, Alg: dpop.AlgEdDSA, JWK: jwk})
	claims := dpop.ProofClaims{JTI: "fixed-jti", HTM: "POST", HTU: "https://as.example.com/oauth/token", IAT: now.Unix()}
	pl, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

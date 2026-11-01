package dpop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
)

func TestAccessTokenHash(t *testing.T) {
	// Vector from RFC 9449 section 7.1 (ath of the example access token).
	const token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	const want = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	tests := []struct {
		name, in, want string
	}{
		{"rfc 9449 example", token, want},
		{"deterministic", token, dpop.AccessTokenHash(token)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dpop.AccessTokenHash(tc.in); got != tc.want {
				t.Fatalf("ath = %q, want %q", got, tc.want)
			}
		})
	}
	if dpop.AccessTokenHash("a") == dpop.AccessTokenHash("b") {
		t.Fatal("distinct tokens must hash differently")
	}
}

func TestNewConfirmationCarriesJKT(t *testing.T) {
	c := dpop.NewConfirmation("thumb")
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"jkt":"thumb"}` {
		t.Fatalf("cnf json = %s", raw)
	}
}

func TestServiceConfigAccessors(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(*dpop.Config)
		wantAge      time.Duration
		wantNonceTTL time.Duration
		wantNonceReq bool
	}{
		{"defaults", func(*dpop.Config) {}, 60 * time.Second, 10 * time.Minute, false},
		{"explicit", func(c *dpop.Config) {
			c.ProofMaxAge = 5 * time.Second
			c.NonceTTL = time.Minute
			c.RequireNonceForTokens = true
		}, 5 * time.Second, time.Minute, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService(t, tc.mutate)
			if svc.ProofMaxAge() != tc.wantAge || svc.NonceTTL() != tc.wantNonceTTL || svc.RequireNonceForTokens() != tc.wantNonceReq {
				t.Fatalf("got %v %v %v", svc.ProofMaxAge(), svc.NonceTTL(), svc.RequireNonceForTokens())
			}
		})
	}
}

// signEdProof builds an EdDSA proof around an arbitrary JWK so verifyEdDSA's key checks run.
func signEdProof(t *testing.T, jwk *dpop.JWK, now time.Time) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := json.Marshal(dpop.ProofHeader{Typ: dpop.ProofTyp, Alg: dpop.AlgEdDSA, JWK: jwk})
	pl, _ := json.Marshal(baseClaims(now))
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

func TestVerifyEdDSARejectsBadKeys(t *testing.T) {
	now := time.Now().UTC()
	good := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	tests := []struct {
		name string
		jwk  *dpop.JWK
		want error
	}{
		{"wrong kty", &dpop.JWK{Kty: "EC", Crv: "Ed25519", X: good}, dpop.ErrMalformedProof},
		{"wrong crv", &dpop.JWK{Kty: "OKP", Crv: "X25519", X: good}, dpop.ErrMalformedProof},
		{"bad base64 x", &dpop.JWK{Kty: "OKP", Crv: "Ed25519", X: "!!!"}, dpop.ErrMalformedProof},
		{"short x", &dpop.JWK{Kty: "OKP", Crv: "Ed25519", X: "AAAA"}, dpop.ErrMalformedProof},
		{"signature from a different key", &dpop.JWK{Kty: "OKP", Crv: "Ed25519", X: good}, dpop.ErrSignatureInvalid},
	}
	svc := newService(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Verify(signEdProof(t, tc.jwk, now), dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyErrorUnwrapsSentinelAndHasMessage(t *testing.T) {
	now := time.Now().UTC()
	proof, _, _ := signedProofES256(t, baseClaims(now), nil)
	_, err := newService(t).Verify(proof, dpop.VerifyParams{Method: "GET", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrMethodMismatch) {
		t.Fatalf("err = %v, want ErrMethodMismatch", err)
	}
	if err.Error() == "" {
		t.Fatal("error message must not be empty")
	}
}

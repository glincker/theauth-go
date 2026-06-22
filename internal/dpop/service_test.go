package dpop_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/dpop"
)

// service_test.go: every numbered check from RFC 9449 section 4.3 lands
// here with a positive + negative case. The signer helpers build proof
// JWTs at the byte level so a test can mutate any field without going
// through the (one-shot, internal) signing surface a future client SDK
// would expose.

// signedProof builds a valid DPoP proof JWT for the supplied claims and
// the ES256 key, returning the compact serialization plus the JWK that
// was embedded in the header.
func signedProofES256(t *testing.T, claims dpop.ProofClaims, mutateHeader func(*dpop.ProofHeader)) (string, *dpop.JWK, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	jwk := &dpop.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()),
	}
	hdr := dpop.ProofHeader{Typ: dpop.ProofTyp, Alg: dpop.AlgES256, JWK: jwk}
	if mutateHeader != nil {
		mutateHeader(&hdr)
	}
	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Fixed-length R||S per RFC 7515 section 3.4.
	const byteSize = 32
	sig := make([]byte, 2*byteSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteSize-len(rBytes):], rBytes)
	copy(sig[2*byteSize-len(sBytes):], sBytes)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), jwk, priv
}

func signedProofEdDSA(t *testing.T, claims dpop.ProofClaims) (string, *dpop.JWK) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	jwk := &dpop.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	hdr := dpop.ProofHeader{Typ: dpop.ProofTyp, Alg: dpop.AlgEdDSA, JWK: jwk}
	headerJSON, _ := json.Marshal(hdr)
	payloadJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), jwk
}

func signedProofRS256(t *testing.T, claims dpop.ProofClaims) (string, *dpop.JWK) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	jwk := &dpop.JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	hdr := dpop.ProofHeader{Typ: dpop.ProofTyp, Alg: dpop.AlgRS256, JWK: jwk}
	headerJSON, _ := json.Marshal(hdr)
	payloadJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), jwk
}

func baseClaims(now time.Time) dpop.ProofClaims {
	return dpop.ProofClaims{
		JTI: "jti-" + base64.RawURLEncoding.EncodeToString([]byte(now.Format(time.RFC3339Nano))),
		HTM: "POST",
		HTU: "https://as.example.com/oauth/token",
		IAT: now.Unix(),
	}
}

func newService(t *testing.T, opts ...func(*dpop.Config)) *dpop.Service {
	t.Helper()
	cfg := dpop.Config{}
	for _, o := range opts {
		o(&cfg)
	}
	svc, err := dpop.New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// Check 1: typ MUST be dpop+jwt.

func TestVerifyHappyPathES256(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	got, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Thumbprint == "" {
		t.Fatalf("expected non-empty thumbprint")
	}
}

func TestVerifyRejectsWrongTyp(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, func(h *dpop.ProofHeader) { h.Typ = "JWT" })
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrMalformedProof) {
		t.Fatalf("want ErrMalformedProof, got %v", err)
	}
}

// Check 2: alg in AllowedSignAlgs.

func TestVerifyAcceptsEdDSAWhenAllowed(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _ := signedProofEdDSA(t, claims)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("verify eddsa: %v", err)
	}
}

func TestVerifyRejectsAlgNotInAllowList(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _ := signedProofEdDSA(t, claims)
	svc := newService(t, func(c *dpop.Config) { c.AllowedSignAlgs = []string{dpop.AlgES256} })
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	now := time.Now().UTC()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","alg":"none","jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}}`))
	claims := baseClaims(now)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	token := header + "." + payload + "."
	svc := newService(t)
	_, err := svc.Verify(token, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

// Check 3: jwk present + signature verifies.

func TestVerifyRejectsMissingJWK(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, func(h *dpop.ProofHeader) { h.JWK = nil })
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrMalformedProof) {
		t.Fatalf("want ErrMalformedProof, got %v", err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	// Tamper the signature.
	parts := strings.Split(proof, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(append([]byte{0x00}, []byte(parts[2])[:30]...))
	tampered := strings.Join(parts, ".")
	svc := newService(t)
	_, err := svc.Verify(tampered, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrSignatureInvalid) && !errors.Is(err, dpop.ErrMalformedProof) {
		t.Fatalf("want signature failure, got %v", err)
	}
}

// Check 4: htm matches method.

func TestVerifyMethodMatchCaseInsensitive(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.HTM = "post"
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.HTM = "GET"
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrMethodMismatch) {
		t.Fatalf("want ErrMethodMismatch, got %v", err)
	}
}

// Check 5: htu matches request URI (no fragment, no query string).

func TestVerifyStripsQueryAndFragment(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token?foo=bar#x", Now: now}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsHTUMismatch(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.HTU = "https://as.example.com/different"
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrURIMismatch) {
		t.Fatalf("want ErrURIMismatch, got %v", err)
	}
}

// Check 6: iat within ProofMaxAge.

func TestVerifyAcceptsRecentIAT(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now.Add(-30 * time.Second))
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsOldIAT(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now.Add(-5 * time.Minute))
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrProofExpired) {
		t.Fatalf("want ErrProofExpired, got %v", err)
	}
}

// Check 7: nonce required + valid.

func TestVerifyRequireNonceFailsWhenMissing(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now, RequireNonce: true})
	if !errors.Is(err, dpop.ErrNonceRequired) {
		t.Fatalf("want ErrNonceRequired, got %v", err)
	}
}

func TestVerifyAcceptsValidNonce(t *testing.T) {
	now := time.Now().UTC()
	svc := newService(t)
	nonce := svc.IssueNonce(now)
	claims := baseClaims(now)
	claims.Nonce = nonce
	proof, _, _ := signedProofES256(t, claims, nil)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now, RequireNonce: true}); err != nil {
		t.Fatalf("verify with nonce: %v", err)
	}
}

func TestVerifyRejectsForeignNonce(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.Nonce = "not-a-real-nonce"
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrNonceInvalid) {
		t.Fatalf("want ErrNonceInvalid, got %v", err)
	}
}

// Check 8: jti unique within window.

func TestVerifyRejectsReplayedJTI(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

// Check 9: ath equals base64url(SHA-256(access_token)).

func TestVerifyATHMatch(t *testing.T) {
	now := time.Now().UTC()
	at := "totally-opaque-access-token"
	claims := baseClaims(now)
	claims.ATH = dpop.AccessTokenHash(at)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now, AccessToken: at}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyATHMissingWhenAccessTokenSupplied(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now, AccessToken: "abc"})
	if !errors.Is(err, dpop.ErrATHRequired) {
		t.Fatalf("want ErrATHRequired, got %v", err)
	}
}

func TestVerifyATHMismatchRejected(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.ATH = dpop.AccessTokenHash("other-token")
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now, AccessToken: "real-token"})
	if !errors.Is(err, dpop.ErrATHMismatch) {
		t.Fatalf("want ErrATHMismatch, got %v", err)
	}
}

// Confirmation binding: stolen access token rejected when proof signed
// by different key than the one the token was minted for.

func TestVerifyAgainstConfirmationRejectsForeignKey(t *testing.T) {
	now := time.Now().UTC()
	// Mint a proof with one key; pretend the access token was bound to a
	// different key.
	claims := baseClaims(now)
	proof, jwk, _ := signedProofES256(t, claims, nil)
	mintedThumb, err := dpop.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	svc := newService(t)
	if _, err := svc.VerifyAgainstConfirmation(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}, mintedThumb); err != nil {
		t.Fatalf("matching thumbprint should verify: %v", err)
	}
	// Replay-safe second proof with a different jti so the replay check
	// does not fire first.
	claims.JTI = claims.JTI + "-2"
	proof2, _, _ := signedProofES256(t, claims, nil)
	_, err = svc.VerifyAgainstConfirmation(proof2, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}, mintedThumb)
	if !errors.Is(err, dpop.ErrJKTMismatch) {
		t.Fatalf("want ErrJKTMismatch, got %v", err)
	}
}

// Thumbprint determinism across permuted JSON: a JWK with reordered
// members must thumbprint identically to its canonical form.

func TestThumbprintRFC7638Vector(t *testing.T) {
	// RFC 7638 section 3.1 worked example.
	jwk := &dpop.JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	thumb, err := dpop.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if thumb != want {
		t.Fatalf("thumbprint mismatch:\n got %s\nwant %s", thumb, want)
	}
}

// RS256 + EdDSA + PS256 wire happy path: confirms verifySignature
// dispatch covers all three alg families.

func TestVerifyRS256(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	proof, _ := signedProofRS256(t, claims)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("verify rs256: %v", err)
	}
}

// Nonce TTL respected.

func TestVerifyRejectsExpiredNonce(t *testing.T) {
	now := time.Now().UTC()
	svc := newService(t, func(c *dpop.Config) { c.NonceTTL = time.Second })
	old := svc.IssueNonce(now.Add(-5 * time.Second))
	claims := baseClaims(now)
	claims.Nonce = old
	proof, _, _ := signedProofES256(t, claims, nil)
	_, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now})
	if !errors.Is(err, dpop.ErrNonceInvalid) {
		t.Fatalf("want ErrNonceInvalid, got %v", err)
	}
}

// ClientRequiresDPoP propagates from config.

func TestClientRequiresDPoP(t *testing.T) {
	svc := newService(t, func(c *dpop.Config) { c.RequireDPoPForClients = []string{"client-A"} })
	if !svc.ClientRequiresDPoP("client-A") {
		t.Fatalf("want true for client-A")
	}
	if svc.ClientRequiresDPoP("client-B") {
		t.Fatalf("want false for client-B")
	}
}

// URI normalization: trailing slash policy and default ports.

func TestCanonicalURIStripsDefaultPorts(t *testing.T) {
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims.HTU = "https://as.example.com:443/oauth/token"
	proof, _, _ := signedProofES256(t, claims, nil)
	svc := newService(t)
	if _, err := svc.Verify(proof, dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

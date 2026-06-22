package mcpresource

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// dpop_test.go: end-to-end coverage for the RFC 9449 sender-constraint
// path. The fake AS mints a JWT carrying cnf.jkt; the validator runs
// every check and rejects (a) requests without DPoP headers, (b) DPoP
// proofs signed by a foreign key, (c) replayed proofs.

// jtiCounter mints unique jti values across the suite so an "ignored"
// helper proof and a real proof signed in the same call frame don't
// trip the verifier's replay window.
var jtiCounter int64

// signDPoPProofES256 builds a valid proof JWT for the given key and
// claim values. Returns the proof string and the JWK thumbprint.
func signDPoPProofES256(t *testing.T, priv *ecdsa.PrivateKey, method, url, accessToken string, iat time.Time) (string, string) {
	t.Helper()
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	athSum := sha256.Sum256([]byte(accessToken))
	jtiCounter++
	claims := map[string]any{
		"jti": fmt.Sprintf("jti-%d-%d", iat.UnixNano(), jtiCounter),
		"htm": method,
		"htu": url,
		"iat": iat.Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(athSum[:]),
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	const byteSize = 32
	sig := make([]byte, 2*byteSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteSize-len(rBytes):], rBytes)
	copy(sig[2*byteSize-len(sBytes):], sBytes)
	canonical := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	thumb := sha256.Sum256([]byte(canonical))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(thumb[:])
}

// newDPoPFakeAS mints a JWKS server signing tokens that carry cnf.jkt
// for the supplied thumbprint. The validator points its JWKS cache at
// the server; introspection is left unconfigured because cnf-bound
// tokens skip the chain walk.
func newDPoPFakeAS(t *testing.T) *fakeAS { return newFakeAS(t) }

func mintDPoPBoundToken(t *testing.T, f *fakeAS, jkt string, exp time.Time) string {
	t.Helper()
	return signToken(t, f.kid, f.priv, map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-1",
		"aud":       "https://files.example.com/mcp",
		"exp":       exp.Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "jti-token-1",
		"client_id": "client-A",
		"scope":     "files.read",
		"cnf":       map[string]string{"jkt": jkt},
	})
}

func TestDPoPHappyPath(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	v := New("https://files.example.com/mcp",
		WithJWKS(f.jwksServer.URL),
		WithDPoPVerification(nil, 0, 0),
	)
	now := time.Now()
	_, thumb := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", "ignored", now)
	token := mintDPoPBoundToken(t, f, thumb, now.Add(time.Hour))
	proof, _ := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", token, now)
	r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	rr := httptest.NewRecorder()
	called := false
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.CnfJKT != thumb {
			t.Fatalf("principal missing or wrong jkt: %+v", p)
		}
	})).ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d body=%s www=%q", rr.Code, rr.Body.String(), rr.Header().Get("WWW-Authenticate"))
	}
	if !called {
		t.Fatalf("inner handler not invoked")
	}
}

func TestDPoPRejectsBearerSchemeWhenCnfBound(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	now := time.Now()
	_, thumb := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", "ignored", now)
	token := mintDPoPBoundToken(t, f, thumb, now.Add(time.Hour))
	r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("must not reach handler")
	})).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", rr.Code)
	}
}

func TestDPoPRejectsForeignKeyProof(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	now := time.Now()
	// Bind token to priv1's jkt.
	_, thumb := signDPoPProofES256(t, priv1, "GET", "https://files.example.com/mcp/x", "ignored", now)
	token := mintDPoPBoundToken(t, f, thumb, now.Add(time.Hour))
	// Sign proof with priv2: stolen-token attack.
	proof, _ := signDPoPProofES256(t, priv2, "GET", "https://files.example.com/mcp/x", token, now)
	r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	rr := httptest.NewRecorder()
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("must not reach handler")
	})).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDPoPRejectsReplayedProof(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	now := time.Now()
	_, thumb := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", "ignored", now)
	token := mintDPoPBoundToken(t, f, thumb, now.Add(time.Hour))
	proof, _ := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", token, now)
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", proof)
		rr := httptest.NewRecorder()
		v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, r)
		if rr.Code != want {
			t.Fatalf("attempt %d: want %d got %d body=%s", i, want, rr.Code, rr.Body.String())
		}
	}
}

func TestDPoPRejectsWrongHTU(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	now := time.Now()
	_, thumb := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/x", "ignored", now)
	token := mintDPoPBoundToken(t, f, thumb, now.Add(time.Hour))
	// Proof claims a different htu than the actual request URL.
	proof, _ := signDPoPProofES256(t, priv, "GET", "https://files.example.com/mcp/y", token, now)
	r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	rr := httptest.NewRecorder()
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("must not reach handler")
	})).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", rr.Code)
	}
}

// Tokens without cnf.jkt continue to flow as Bearer (back compat).
func TestBearerStillWorksWhenDPoPEnabled(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	exp := time.Now().Add(time.Hour)
	token := signToken(t, f.kid, f.priv, map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-1",
		"aud":       "https://files.example.com/mcp",
		"exp":       exp.Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "jti-noncnf",
		"client_id": "client-B",
		"scope":     "files.read",
	})
	r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	called := false
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).ServeHTTP(rr, r)
	if rr.Code != http.StatusOK || !called {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func ed25519Pub(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

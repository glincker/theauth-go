package mcpresource

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// benchValidate drives the middleware directly with prebuilt requests so the loop measures token
// validation (signature, claims, DPoP, revocation checker) and not request construction.
func benchValidate(b *testing.B, v *Validator, reqs []*http.Request) {
	b.Helper()
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Code = 200
		h.ServeHTTP(w, reqs[i%len(reqs)])
		if w.Code != http.StatusOK {
			b.Fatalf("status %d", w.Code)
		}
	}
}

func benchBearerRequests(n int, token string) []*http.Request {
	reqs := make([]*http.Request, n)
	for i := range reqs {
		r := httptest.NewRequest(http.MethodGet, testResource+"/tools", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		reqs[i] = r
	}
	return reqs
}

func benchClaims(extra map[string]any) map[string]any {
	c := map[string]any{
		"iss": testResource, "sub": "spiffe://example.org/sensor", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "jti-bench", "client_id": "dev-1", "scope": "telemetry:write",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// BenchmarkValidateBearer is the floor: Ed25519 verify, claim checks, principal build.
func BenchmarkValidateBearer(b *testing.B) {
	f := newFakeAS(b)
	v := New(testResource, WithJWKS(f.jwksServer.URL))
	tok := signToken(b, f.kid, f.priv, benchClaims(nil))
	benchValidate(b, v, benchBearerRequests(1, tok))
}

// BenchmarkValidateBearerRevocation adds a RevocationChecker that answers from memory, which is
// the cost the middleware itself adds on top of the checker.
func BenchmarkValidateBearerRevocation(b *testing.B) {
	f := newFakeAS(b)
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithRevocationChecker(
		RevocationCheckerFunc(func(context.Context, string, *Principal) (bool, error) { return false, nil })))
	tok := signToken(b, f.kid, f.priv, benchClaims(map[string]any{"device_id": "01DEV"}))
	benchValidate(b, v, benchBearerRequests(1, tok))
}

// BenchmarkValidateDPoP is the sender constrained path: a unique ES256 proof per request (the
// replay cache would refuse a repeat), verified and bound to the access token.
func BenchmarkValidateDPoP(b *testing.B) {
	f := newFakeAS(b)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	url := testResource + "/tools"
	_, thumb := signDPoPProofES256(b, priv, "GET", url, "x", now)
	tok := signToken(b, f.kid, f.priv, benchClaims(map[string]any{"cnf": map[string]string{"jkt": thumb}}))
	reqs := make([]*http.Request, b.N)
	for i := range reqs {
		proof, _ := signDPoPProofES256(b, priv, "GET", url, tok, now)
		r := httptest.NewRequest(http.MethodGet, url, nil)
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", proof)
		reqs[i] = r
	}
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, b.N+16))
	benchValidate(b, v, reqs)
}

// BenchmarkValidateDPoPRevocation is DPoP plus a revocation checker.
func BenchmarkValidateDPoPRevocation(b *testing.B) {
	f := newFakeAS(b)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	url := testResource + "/tools"
	_, thumb := signDPoPProofES256(b, priv, "GET", url, "x", now)
	tok := signToken(b, f.kid, f.priv, benchClaims(map[string]any{"device_id": "01DEV", "cnf": map[string]string{"jkt": thumb}}))
	reqs := make([]*http.Request, b.N)
	for i := range reqs {
		proof, _ := signDPoPProofES256(b, priv, "GET", url, tok, now)
		r := httptest.NewRequest(http.MethodGet, url, nil)
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", proof)
		reqs[i] = r
	}
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, b.N+16),
		WithRevocationChecker(RevocationCheckerFunc(func(context.Context, string, *Principal) (bool, error) { return false, nil })))
	benchValidate(b, v, reqs)
}

// BenchmarkValidateBearerParallel checks lock contention on the JWKS cache and the middleware.
func BenchmarkValidateBearerParallel(b *testing.B) {
	f := newFakeAS(b)
	v := New(testResource, WithJWKS(f.jwksServer.URL))
	tok := signToken(b, f.kid, f.priv, benchClaims(nil))
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := httptest.NewRequest(http.MethodGet, testResource+"/tools", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		for pb.Next() {
			w.Code = 200
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				b.Fatalf("status %d", w.Code)
			}
		}
	})
}

// BenchmarkValidateDeviceRevocationIntrospection is the built in device revocation check with a
// warm introspection cache: a token hash plus one read locked map lookup per request.
func BenchmarkValidateDeviceRevocationIntrospection(b *testing.B) {
	f := newFakeAS(b)
	v := New(testResource, WithJWKS(f.jwksServer.URL),
		WithIntrospection(f.introspectServer.URL, "client-1", "secret-1"), WithDeviceRevocationIntrospection())
	tok := signToken(b, f.kid, f.priv, benchClaims(map[string]any{"device_id": "01DEV"}))
	reqs := benchBearerRequests(1, tok)
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqs[0]) // warm the cache
	if w.Code != http.StatusOK {
		b.Fatalf("warm up status %d", w.Code)
	}
	benchValidate(b, v, reqs)
}

package mcpresource

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// signToken builds an EdDSA JWT with the supplied claim map. Used in every
// test to mint tokens that match the AS shape.
func signToken(t *testing.T, kid string, priv ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "EdDSA", "typ": "at+jwt", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// fakeAS bundles a JWKS server, an introspection server, a signing key, and
// the ability to flip the introspection answer between active and inactive.
type fakeAS struct {
	jwksServer       *httptest.Server
	introspectServer *httptest.Server
	priv             ed25519.PrivateKey
	pub              ed25519.PublicKey
	kid              string

	introspectActive atomic.Bool
	introspectCalls  atomic.Int64
	jwksCalls        atomic.Int64
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}
	kid := "kid-1"
	f := &fakeAS{priv: priv, pub: pub, kid: kid}
	f.introspectActive.Store(true)

	f.jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.jwksCalls.Add(1)
		doc := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
					"alg": "EdDSA",
					"use": "sig",
					"kid": kid,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	f.introspectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.introspectCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":    f.introspectActive.Load(),
			"client_id": "client-1",
			"scope":     "read",
		})
	}))
	t.Cleanup(func() {
		f.jwksServer.Close()
		f.introspectServer.Close()
	})
	return f
}

const testResource = "https://mcp.example.com"

func newValidatorAgainst(f *fakeAS) *Validator {
	return New(testResource,
		WithJWKS(f.jwksServer.URL),
		WithIntrospection(f.introspectServer.URL, "client-1", "secret-1"),
		WithCacheTTL(60*time.Second),
	)
}

func TestMiddleware_SignaturePass(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss":       testResource,
		"sub":       "user-1",
		"aud":       testResource,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "jti-1",
		"client_id": "client-1",
		"scope":     "read write",
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_SignatureFail(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "user-1", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "jti-1", "client_id": "client-1", "scope": "read",
	})
	// Corrupt the signature.
	parts := strings.Split(tok, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("garbage-garbage-garbage-garbage-garbage-garbage-garbage-garbage-garbage-garbage"))
	tampered := strings.Join(parts, ".")
	rec := runMiddleware(v, "Bearer "+tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("missing WWW-Authenticate invalid_token: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddleware_AudienceMismatch(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "user-1", "aud": "https://other.example.com",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "jti-1", "client_id": "client-1", "scope": "read",
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMiddleware_ExpiredToken(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "user-1", "aud": testResource,
		"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(),
		"jti": "jti-1", "client_id": "client-1", "scope": "read",
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMiddleware_ChainWalkHappyPath(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss":       testResource,
		"sub":       "user-1",
		"aud":       testResource,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "jti-2",
		"client_id": "client-1",
		"scope":     "read",
		"act": map[string]any{
			"sub": "agent:01ABCDE",
		},
		"delegation_grant_id": "01GRANT",
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddleware_ChainWalkRevoked(t *testing.T) {
	f := newFakeAS(t)
	f.introspectActive.Store(false)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss":       testResource,
		"sub":       "user-1",
		"aud":       testResource,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "jti-3",
		"client_id": "client-1",
		"scope":     "read",
		"act":       map[string]any{"sub": "agent:01ABCDE"},
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked chain, got %d", rec.Code)
	}
}

func TestJWKS_KidMissRefresh(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	// First request primes the JWKS cache.
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "a", "client_id": "c", "scope": "s",
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("priming call failed: %d", rec.Code)
	}
	priorJWKSCalls := f.jwksCalls.Load()
	// Now sign a token with a *new* kid. The cache should hit a miss and
	// re-fetch JWKS, but the kid won't be present so the request fails.
	tok2 := signToken(t, "kid-unknown", f.priv, map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "b", "client_id": "c", "scope": "s",
	})
	v.jwks.minRefreshInterval = 0
	rec2 := runMiddleware(v, "Bearer "+tok2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown kid, got %d", rec2.Code)
	}
	if f.jwksCalls.Load() <= priorJWKSCalls {
		t.Fatalf("expected JWKS refresh on kid miss; jwksCalls=%d", f.jwksCalls.Load())
	}
}

func TestIntrospection_CacheTTL(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss":       testResource,
		"sub":       "user-1",
		"aud":       testResource,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "cache-tok",
		"client_id": "c",
		"scope":     "read",
		"act":       map[string]any{"sub": "agent:01ABC"},
	})
	for i := 0; i < 5; i++ {
		rec := runMiddleware(v, "Bearer "+tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d failed: %d", i, rec.Code)
		}
	}
	if f.introspectCalls.Load() != 1 {
		t.Fatalf("expected 1 introspection call (cache hits), got %d", f.introspectCalls.Load())
	}
}

func TestMissingBearer(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	rec := runMiddleware(v, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	auth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(auth, "resource_metadata") {
		t.Fatalf("expected resource_metadata pointer in WWW-Authenticate, got %q", auth)
	}
}

// runMiddleware executes the Validator middleware against a fake handler and
// returns the response recorder.
func runMiddleware(v *Validator, authHeader string) *httptest.ResponseRecorder {
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := v.Principal(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "ok %s", p.Subject)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/tools", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	h.ServeHTTP(rec, req)
	return rec
}

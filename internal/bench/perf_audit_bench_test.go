package bench

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// perf_audit_bench_test.go covers the cached client secret verify and the cached JWKS signing key,
// the two hot paths of the perf audit.

const (
	perfBenchClientID = "perf-bench-client"
	perfBenchResource = "https://files.example.com/mcp"
)

// seedRefreshToken inserts a fresh refresh token and returns it, for single-shot refresh grant benchmarks.
func seedRefreshToken(tb testing.TB, store *memory.Store, clientID string, userID theauth.ULID, resource string) string {
	tb.Helper()
	tok, err := crypto.NewToken()
	if err != nil {
		tb.Fatal(err)
	}
	hash := crypto.HashToken(tok)
	now := time.Now().UTC()
	if err := store.InsertRefreshToken(context.Background(), theauth.RefreshToken{
		ID:        ulid.New(),
		Hash:      hash,
		FamilyID:  ulid.New(),
		ClientID:  clientID,
		UserID:    &userID,
		Scope:     []string{"files.read"},
		Resource:  resource,
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}); err != nil {
		tb.Fatal(err)
	}
	return tok
}

// buildTokenRequest constructs an /oauth/token POST request with
// client_secret_basic auth carrying the refresh_token grant body.
func buildTokenRequest(clientID, clientSecret, refreshToken, resource string) *http.Request {
	form := "grant_type=refresh_token" +
		"&refresh_token=" + refreshToken +
		"&resource=" + resource
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := clientID + ":" + clientSecret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req
}

// BenchmarkOAuthTokenEndpointRefreshHit drives the refresh_token grant over HTTP with a warm Argon2
// cache. The audit expected the cached path to be far faster than the 27 ms uncached baseline.
func BenchmarkOAuthTokenEndpointRefreshHit(b *testing.B) {
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: perfBenchResource, Scopes: []string{"files.read"}}},
			DisableRotation: true,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)
	secret, err := crypto.NewToken()
	if err != nil {
		b.Fatal(err)
	}
	hash, err := crypto.HashPassword(secret)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.InsertOAuthClient(context.Background(), theauth.OAuthClient{
		ID:                      ulid.New(),
		ClientID:                perfBenchClientID,
		ClientSecretHash:        []byte(hash),
		ClientName:              "perf-bench",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{theauth.GrantTypeRefreshToken, theauth.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{theauth.ResponseTypeCode},
		TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
		CreatedAt:               now,
		UpdatedAt:               now,
	}); err != nil {
		b.Fatal(err)
	}
	userID := ulid.New()
	r := chi.NewRouter()
	a.Mount(r)

	// Pre-seed the cache with one warm-up call so b.N iterations only
	// measure the hot path.
	warmTok := seedRefreshToken(b, store, perfBenchClientID, userID, perfBenchResource)
	warm := buildTokenRequest(perfBenchClientID, secret, warmTok, perfBenchResource)
	warmRec := httptest.NewRecorder()
	r.ServeHTTP(warmRec, warm)
	if warmRec.Code != http.StatusOK {
		b.Fatalf("warmup token grant: %d %s", warmRec.Code, warmRec.Body.String())
	}

	// Pre-seed N refresh tokens so the benchmark loop itself does not pay
	// the seedRefreshToken storage insert cost on the measured path.
	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		tokens[i] = seedRefreshToken(b, store, perfBenchClientID, userID, perfBenchResource)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := buildTokenRequest(perfBenchClientID, secret, tokens[i], perfBenchResource)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("token grant iter %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkJWKSSigningKeyAccess is a smoke benchmark of the snapshot read behind every mint. The
// real win shows on the token endpoint.
func BenchmarkJWKSEndpoint(b *testing.B) {
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: perfBenchResource, Scopes: []string{"files.read"}}},
			DisableRotation: true,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	jwksReq := httptest.NewRequest(http.MethodGet, "/oauth/jwks", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, jwksReq)
		if rec.Code != http.StatusOK {
			b.Fatalf("jwks status %d", rec.Code)
		}
		_ = rec.Body.Bytes()
	}
}

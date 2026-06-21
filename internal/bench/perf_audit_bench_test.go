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

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// perf_audit_bench_test.go: new benchmarks added by the 2026-06-20 perf
// audit landing PR (perf/audit-top3-2026-06-20). These cover the two
// hot paths the audit identified as bottlenecks that this package can
// reach without going through unexported helpers:
//
//   1. Client_secret verification (Argon2id) cached on a sha256-keyed LRU
//      keyed by client_id. Measured at the /oauth/token endpoint via
//      httptest, since that is the production hot path and the cache lives
//      one stack frame inside the public authenticateClient helper.
//      Before: ~27 ms/op via VerifyPassword on every call.
//      After:  ~1-50 us/op when the cache hits; cache miss still ~27 ms.
//
//   2. JWKS signing key load (AES-GCM decrypt) cached on the snapshot.
//      Measured indirectly: every /oauth/token call mints a JWT and so
//      consumes one currentSigningKey call. Cache miss pays AES decrypt
//      plus ed25519 NewKeyFromSeed; cache hit pays one map lookup.
//
// The MCP introspect cache RWMutex change is exercised by the package's
// own race test under `go test -race`; benchmarking lock acquisition is
// dominated by net/http loopback noise.

const (
	perfBenchClientID = "perf-bench-client"
	perfBenchResource = "https://files.example.com/mcp"
)

// seedRefreshToken inserts a fresh refresh token into the store and returns
// it. Used by benchmarks that need a single-shot refresh_token grant per
// iteration. The token + family-id combo is unique per call.
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

// BenchmarkOAuthTokenEndpointRefreshHit drives /oauth/token (refresh_token
// grant) through the full HTTP path with a CACHED Argon2 verification. The
// first iteration of the benchmark seeds the cache; b.N iterations after
// that hit the cache, which is what the audit's "50x faster" gate measures.
//
// Pre-cache audit baseline: 27.6 ms/op, 67 MB/op, 241 allocs/op
// (BenchmarkASIntrospectHit in the audit harness; the introspect and the
// token endpoint share authenticateClient and therefore share the
// dominating Argon2 cost). Post-cache expectation per the audit:
// 50-200 us/op.
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

// BenchmarkJWKSSigningKeyAccess measures the cached signing-key access in
// isolation. Re-creates the AS once, then drives a synthetic /oauth/jwks
// GET through the public router (which under the hood reads the snapshot
// the private-key cache lives on; the public document endpoint doesn't
// consume the private key, but the cost of the snapshot read is a tight
// upper bound on the privKeyByKID lookup cost).
//
// This is a smoke benchmark: the real win shows up on /oauth/token
// (covered above), because every mint pays one currentSigningKey call.
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

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

const (
	codeFlowClientID = "code-flow-bench-client"
	codeFlowResource = "https://files.example.com/mcp"
	codeFlowRedirect = "https://app.example.com/callback"
)

// BenchmarkOAuthCodeFlow measures the /oauth/token authorization_code grant
// end-to-end through the full HTTP handler path: client authentication (with
// the Argon2 cache warm), PKCE S256 verification, authorization code
// consume, JWT mint, refresh token insert, and response marshal. This is the
// primary path a first-time user exercises after the browser redirect.
//
// Each iteration seeds a new authorization code so the consume is always
// fresh. Client-secret verification is cache-warm (seeded in setup) so the
// Argon2 cost does not dominate and we measure the protocol work.
//
// gate:include
func BenchmarkOAuthCodeFlow(b *testing.B) {
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
			Resources:       []theauth.ProtectedResource{{Identifier: codeFlowResource, Scopes: []string{"files.read"}}},
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
		ClientID:                codeFlowClientID,
		ClientSecretHash:        []byte(hash),
		ClientName:              "code-flow-bench",
		RedirectURIs:            []string{codeFlowRedirect},
		GrantTypes:              []string{theauth.GrantTypeAuthorizationCode, theauth.GrantTypeRefreshToken},
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

	// Warm up the client-secret cache so measured iterations hit the fast path.
	verifier, err := crypto.NewCodeVerifier()
	if err != nil {
		b.Fatal(err)
	}
	challenge := crypto.CodeChallenge(verifier)
	warmCode := insertAuthCode(b, store, codeFlowClientID, userID, challenge)
	warmBody := codeGrantBody(warmCode, verifier)
	warmReq := buildCodeTokenRequest(codeFlowClientID, secret, warmBody)
	warmRec := httptest.NewRecorder()
	r.ServeHTTP(warmRec, warmReq)
	if warmRec.Code != http.StatusOK {
		b.Fatalf("warmup code grant: %d %s", warmRec.Code, warmRec.Body.String())
	}

	// Pre-generate N PKCE pairs and seed N authorization codes so the
	// measured path does not include setup overhead.
	type codeEntry struct {
		code     string
		verifier string
	}
	codes := make([]codeEntry, b.N)
	for i := 0; i < b.N; i++ {
		v, err := crypto.NewCodeVerifier()
		if err != nil {
			b.Fatal(err)
		}
		ch := crypto.CodeChallenge(v)
		codes[i] = codeEntry{
			code:     insertAuthCode(b, store, codeFlowClientID, userID, ch),
			verifier: v,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body := codeGrantBody(codes[i].code, codes[i].verifier)
		req := buildCodeTokenRequest(codeFlowClientID, secret, body)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("code grant iter %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

// insertAuthCode seeds a fresh authorization code row in the store and
// returns the plaintext code. The code expires in 60 seconds.
func insertAuthCode(tb testing.TB, store *memory.Store, clientID string, userID theauth.ULID, challenge string) string {
	tb.Helper()
	rawCode := make([]byte, 32)
	if _, err := rand.Read(rawCode); err != nil {
		tb.Fatal(err)
	}
	code := base64.RawURLEncoding.EncodeToString(rawCode)
	now := time.Now().UTC()
	if err := store.InsertAuthorizationCode(context.Background(), theauth.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         codeFlowRedirect,
		Scope:               []string{"files.read"},
		Resource:            codeFlowResource,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(60 * time.Second),
		CreatedAt:           now,
	}); err != nil {
		tb.Fatal(err)
	}
	return code
}

// codeGrantBody returns the URL-encoded body for an authorization_code grant.
func codeGrantBody(code, verifier string) string {
	return "grant_type=authorization_code" +
		"&code=" + code +
		"&redirect_uri=" + codeFlowRedirect +
		"&code_verifier=" + verifier +
		"&resource=" + codeFlowResource
}

// buildCodeTokenRequest creates the /oauth/token POST with client_secret_basic.
func buildCodeTokenRequest(clientID, secret, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := clientID + ":" + secret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req
}

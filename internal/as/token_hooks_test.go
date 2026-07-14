package as_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// decodeJWTPayload base64url-decodes the middle segment of a JWT and
// unmarshals it into a map, so the test can assert on claims that
// IntrospectionResponse does not surface (arbitrary custom claims land in
// the JWT's Extra set, not in the typed introspection response fields).
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

// TestOnTokenIssuedAddsClaimAndCanAbort proves LifecycleHooks.OnTokenIssued
// fires on the authorization_code grant, that its returned map lands in
// the signed JWT's Extra claims, and that a non-nil error aborts issuance
// entirely (no token minted) per the documented "OnTokenIssued is the only
// hook permitted to mutate state" contract in config.go.
func TestOnTokenIssuedAddsClaimAndCanAbort(t *testing.T) {
	var (
		mu    sync.Mutex
		calls int
		abort bool
	)

	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
			DisableRotation: true,
		},
		LifecycleHooks: &theauth.LifecycleHooks{
			OnTokenIssued: func(ctx context.Context, claims map[string]any) (map[string]any, error) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				if abort {
					return nil, errors.New("token issuance blocked by policy")
				}
				claims["org_tier"] = "gold"
				return claims, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()

	user := theauth.User{ID: ulid.New(), Email: "hooks-token@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	client := confidentialClient(t, a)

	mintToken := func(t *testing.T) (theauth.TokenResponse, error) {
		t.Helper()
		verifier, _ := crypto.NewCodeVerifier()
		res, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
			ClientID:            client.ClientID,
			RedirectURI:         "https://app.example.com/cb",
			ResponseType:        "code",
			Scope:               []string{"files.read"},
			CodeChallenge:       crypto.CodeChallenge(verifier),
			CodeChallengeMethod: "S256",
			Resource:            "https://files.example.com/mcp",
		}, &user)
		if err != nil {
			t.Fatalf("StartAuthorize: %v", err)
		}
		code := codeFromRedirect(t, res.RedirectURL)
		return a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
			GrantType:    theauth.GrantTypeAuthorizationCode,
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Code:         code,
			CodeVerifier: verifier,
			RedirectURI:  "https://app.example.com/cb",
		})
	}

	tok, err := mintToken(t)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	mu.Lock()
	if calls != 1 {
		t.Fatalf("want 1 OnTokenIssued call, got %d", calls)
	}
	mu.Unlock()
	claims := decodeJWTPayload(t, tok.AccessToken)
	if claims["org_tier"] != "gold" {
		t.Fatalf("expected org_tier=gold in signed JWT, got %+v", claims)
	}

	mu.Lock()
	abort = true
	mu.Unlock()
	if _, err := mintToken(t); err == nil {
		t.Fatal("expected ExchangeAuthorizationCode to fail when OnTokenIssued errors")
	}
	mu.Lock()
	if calls != 2 {
		t.Fatalf("want 2 OnTokenIssued calls after the aborted attempt, got %d", calls)
	}
	mu.Unlock()
}

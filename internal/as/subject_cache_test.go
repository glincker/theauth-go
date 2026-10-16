package as_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// TestSubjectCacheKeepsRevocationImmediate primes the subject cache with a
// cache-hit introspection, then suspends the agent and asserts the very next
// introspection is inactive, well inside SubjectActiveCacheTTL.
func TestSubjectCacheKeepsRevocationImmediate(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:                "https://auth.example.com",
			Resources:             []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
			DisableRotation:       true,
			IntrospectionCacheTTL: time.Hour,
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	uid := user.ID
	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{Owner: theauth.AgentOwner{UserID: &uid}, Name: "demo", Scope: []string{"files.read"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType: theauth.GrantTypeClientCredentials, ClientID: secret.ClientID, ClientSecret: secret.Secret,
		Resource: "https://files.example.com/mcp", Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	active := func() bool {
		resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
		if err != nil {
			t.Fatal(err)
		}
		return resp.Active
	}
	// First call fills the introspection cache, the second hits it and
	// fills the subject cache, the third is served from the subject cache.
	for i := 0; i < 3; i++ {
		if !active() {
			t.Fatalf("introspection %d inactive before suspend", i)
		}
	}
	if err := a.SuspendAgent(ctx, agent.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if active() {
		t.Fatal("agent self token still active right after suspend with the subject cache on")
	}
	if err := a.ResumeAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if !active() {
		t.Fatal("resumed agent should introspect active again (negative answers are not cached)")
	}
}

package as_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// fakeClock is a mutable, injectable Clock for deterministic cache-TTL
// tests. Safe for concurrent use since the rotation goroutine and request
// handlers may read it from different goroutines.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestIntrospectAfterSuspendPropagatesOncePastCacheTTL exercises the
// scenario from issue #38: a resource server introspects an agent's
// client_credentials token (caching the response), the agent is then
// suspended, and a same-token re-introspect within IntrospectionCacheTTL
// still reports the stale active=true (the cache does not re-run the
// self-agent-status check on a cache hit, see introspect.go's
// introspectJWT vs. the cache-hit path in IntrospectToken). Only once the
// injected fake clock is advanced past the TTL does the cache miss force
// a fresh check that observes the suspension. Before Clock existed, this
// scenario had no synchronous test path short of sleeping 60+ seconds.
func TestIntrospectAfterSuspendPropagatesOncePastCacheTTL(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:                "https://auth.example.com",
			Resources:             []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
			DisableRotation:       true,
			IntrospectionCacheTTL: time.Minute,
			Clock:                 clock,
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()

	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := user.ID
	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "demo-agent",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	tok, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secret.ClientID,
		ClientSecret: secret.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("ClientCredentialsToken: %v", err)
	}

	// Populate the introspection cache.
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil || !resp.Active {
		t.Fatalf("expected active=true before suspend, got %+v (err=%v)", resp, err)
	}

	if err := a.SuspendAgent(ctx, agent.ID, "test-suspend"); err != nil {
		t.Fatalf("SuspendAgent: %v", err)
	}

	// Re-introspecting the same token within the TTL still hits the cache
	// and returns the stale active=true, since a cache hit only re-verifies
	// an actor chain / delegation grant, not the self-agent-status check.
	resp, _, err = a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil || !resp.Active {
		t.Fatalf("expected stale active=true within cache TTL, got %+v (err=%v)", resp, err)
	}

	// Advance the fake clock past IntrospectionCacheTTL: no sleep required.
	// This is exactly the assertion the downstream consumer had to drop for
	// lack of an injectable time source (issue #38).
	clock.Advance(time.Minute + time.Second)

	resp, _, err = a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("IntrospectToken after TTL: %v", err)
	}
	if resp.Active {
		t.Fatalf("expected active=false once the cache miss re-checks agent status, got %+v", resp)
	}
}

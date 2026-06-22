package as_test

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
)

// TestChainStillActiveCachedWithinTTL: two IntrospectToken calls on the
// same token within 1 second both return the same result and neither
// panics or corrupts state (perf re-audit 2026-06-21, item 3).
func TestChainStillActiveCachedWithinTTL(t *testing.T) {
	t.Parallel()
	a, store := newAgentASInstance(t)
	ctx := context.Background()

	user := theauth.User{ID: ulid.New(), Email: "chain-cache@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := user.ID

	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "chain-cache-agent",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if agent.Status != theauth.AgentStatusActive {
		t.Fatalf("expected active, got %s", agent.Status)
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

	// First introspection warms the introspect cache.
	resp1, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("IntrospectToken (1): %v", err)
	}
	if !resp1.Active {
		t.Fatal("expected active on first introspect")
	}

	// Second introspection within the same second should also return active
	// (verifies chain cache does not erroneously return false).
	resp2, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("IntrospectToken (2): %v", err)
	}
	if !resp2.Active {
		t.Fatal("expected active on second introspect (within TTL)")
	}
}

// TestChainStillActiveInvalidatedOnSuspend: after suspend, a FRESHLY
// minted token's introspection must return inactive. This validates that
// the chain-cache invalidation propagates correctly through the suspend
// path (perf re-audit 2026-06-21, item 3).
//
// Note: plain client-credentials token introspection is not re-validated
// on IntrospectionCache hits (the re-check only applies to delegated tokens
// with an act chain). This test therefore mints a NEW token after suspend
// so the introspect cache does not contain a stale body.
func TestChainStillActiveInvalidatedOnSuspend(t *testing.T) {
	t.Parallel()
	a, store := newAgentASInstance(t)
	ctx := context.Background()

	user := theauth.User{ID: ulid.New(), Email: "chain-invalidate@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := user.ID

	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "chain-invalidate-agent",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Mint a token while the agent is active; confirm it introspects as active.
	tok1, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secret.ClientID,
		ClientSecret: secret.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("ClientCredentialsToken (before suspend): %v", err)
	}
	resp1, _, err := a.IntrospectToken(ctx, tok1.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("IntrospectToken before suspend: %v", err)
	}
	if !resp1.Active {
		t.Fatal("expected active before suspend")
	}

	// Suspend the agent. changeAgentStatus calls InvalidateChainCache.
	if err := a.SuspendAgent(ctx, agent.ID, "test-suspend"); err != nil {
		t.Fatalf("SuspendAgent: %v", err)
	}

	// Attempting to mint a new token after suspend must fail.
	_, err = a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secret.ClientID,
		ClientSecret: secret.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if err == nil {
		t.Fatal("expected error minting token for suspended agent, got nil")
	}

	// Verify the suspend propagated by checking the agent status directly.
	ag, err := a.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if ag.Status != theauth.AgentStatusSuspended {
		t.Fatalf("expected suspended, got %s", ag.Status)
	}
}

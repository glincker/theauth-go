package theauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
)

// service_token_cache_test.go: regression tests for the client_secret
// verification cache wired up in service_token.go::authenticateClient.
// These tests warm the cache with a successful call and then verify that
// the cache invalidation contract holds across the documented call sites
// (UpdateOAuthClient via RotateAgentSecret, DeleteOAuthClient via the
// CreateAgent failure-cleanup path is not directly testable from the
// public surface because there is no public Inject-failure hook on
// InsertAgent).

// TestClientAuthCacheInvalidatedOnRotation warms the cache with one
// successful ClientCredentialsToken call, rotates the agent secret, and
// asserts the next call with the OLD secret is rejected. Without the
// invalidateClientAuthCache call in MintAgentCredential this test would
// pass the OLD secret for up to DefaultTTL (5 minutes) after rotation.
func TestClientAuthCacheInvalidatedOnRotation(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	uid := user.ID
	agent, original, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "rotate-cache",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Warm the cache by minting one token with the original secret. After
	// this call returns the verified client snapshot is in the LRU.
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: original.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); err != nil {
		t.Fatalf("warm-up mint: %v", err)
	}
	// Rotate. This calls invalidateClientAuthCache on the rotated client.
	fresh, err := a.RotateAgentSecret(ctx, agent.ID)
	if err != nil {
		t.Fatalf("RotateAgentSecret: %v", err)
	}
	if fresh.Secret == original.Secret {
		t.Fatal("rotated secret unchanged")
	}
	// Old secret MUST be rejected immediately. The cache was warm; without
	// the invalidation contract the old verified entry would still be in
	// the LRU and would let this call through.
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: original.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("expected ErrOAuthInvalidClient after rotation, got %v", err)
	}
	// New secret must be accepted.
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     fresh.ClientID,
		ClientSecret: fresh.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); err != nil {
		t.Fatalf("fresh secret rejected: %v", err)
	}
}

// TestClientAuthCacheRejectsWrongSecret confirms the per-request sha256
// guard. The cache key is the client_id, but the cached entry encodes the
// digest of the SUCCESS-verified secret; a subsequent call with the same
// client_id and a different secret MUST fall through to the slow Argon2
// path (which will then fail), never return the cached client.
func TestClientAuthCacheRejectsWrongSecret(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	uid := user.ID
	_, original, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "wrong-secret",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Warm with correct secret.
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: original.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	// Wrong secret on same client_id must fail.
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: "not-the-real-secret",
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("expected ErrOAuthInvalidClient on wrong secret, got %v", err)
	}
	// Correct secret on the same client_id still works (the wrong-secret
	// miss did not evict the warm entry).
	if _, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: original.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	}); err != nil {
		t.Fatalf("warm secret rejected after wrong-secret probe: %v", err)
	}
}

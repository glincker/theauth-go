package theauth_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// newAgentASInstance wires the same AS harness as newASInstance plus the
// Phase 3 + 4 Config.AgentIdentity block. Returned alongside the in-memory
// store so tests can stamp users and inspect agent rows directly.
func newAgentASInstance(t *testing.T, mut ...func(*theauth.AuthorizationServerConfig)) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:          "https://auth.example.com",
		Resources:       []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read", "files.write"}}},
		DisableRotation: true,
	}
	for _, m := range mut {
		m(asCfg)
	}
	a, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://auth.example.com",
		EncryptionKey:       key,
		AuthorizationServer: asCfg,
		AgentIdentity:       &theauth.AgentConfig{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func TestCreateAgentAndClientCredentials(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
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
	if agent.Status != theauth.AgentStatusActive {
		t.Fatalf("new agent should be active, got %s", agent.Status)
	}
	if secret.Secret == "" || secret.ClientID == "" {
		t.Fatalf("secret missing: %+v", secret)
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
	if tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("unexpected token response: %+v", tok)
	}
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatalf("expected active, got %+v", resp)
	}
	wantSub := theauth.AgentSubjectPrefix + agent.ID.String()
	if resp.Sub != wantSub {
		t.Fatalf("agent token sub: want %s, got %s", wantSub, resp.Sub)
	}
}

func TestClientCredentialsDeniedWhenAgentSuspended(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	_, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "demo",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ag, _ := a.ListAgentsByOwner(ctx, theauth.AgentOwner{UserID: &uid})
	if len(ag) != 1 {
		t.Fatalf("ListAgentsByOwner: want 1, got %d", len(ag))
	}
	if err := a.SuspendAgent(ctx, ag[0].ID, "investigation"); err != nil {
		t.Fatal(err)
	}
	_, err = a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secret.ClientID,
		ClientSecret: secret.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if !errors.Is(err, theauth.ErrAgentInactive) {
		t.Fatalf("expected ErrAgentInactive, got %v", err)
	}
}

func TestRotateAgentSecretRevokesPriorCredential(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	agent, original, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "demo",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := a.RotateAgentSecret(ctx, agent.ID)
	if err != nil {
		t.Fatalf("RotateAgentSecret: %v", err)
	}
	if fresh.Secret == original.Secret {
		t.Fatal("rotated secret should differ from the original")
	}
	_, err = a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     original.ClientID,
		ClientSecret: original.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("expected invalid_client on old secret, got %v", err)
	}
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

func TestMintAgentCredentialOnlyAcceptsSecretKind(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	agent, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "demo",
		Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.MintAgentCredential(ctx, agent.ID, theauth.AgentCredentialKindX509); !errors.Is(err, theauth.ErrNotImplemented) {
		t.Fatalf("x509 kind: want ErrNotImplemented, got %v", err)
	}
	if _, err := a.MintAgentCredential(ctx, agent.ID, theauth.AgentCredentialKindJWK); !errors.Is(err, theauth.ErrNotImplemented) {
		t.Fatalf("jwk kind: want ErrNotImplemented, got %v", err)
	}
}

func TestNewRejectsAgentWithoutAS(t *testing.T) {
	store := memory.New()
	_, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://x",
		AgentIdentity: &theauth.AgentConfig{},
	})
	if !errors.Is(err, theauth.ErrAgentRequiresAS) {
		t.Fatalf("expected ErrAgentRequiresAS, got %v", err)
	}
}

func TestNewRejectsChainDepthAboveCeiling(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://x",
		EncryptionKey:       key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "https://auth.example.com"},
		AgentIdentity:       &theauth.AgentConfig{MaxChainDepth: 5},
	})
	if !errors.Is(err, theauth.ErrAgentChainDepthTooHigh) {
		t.Fatalf("expected ErrAgentChainDepthTooHigh, got %v", err)
	}
}

package memory_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storage/memory"
)

// memory_v20_test verifies the in-memory adapter satisfies the v2.0 (phase
// 1 + 2) OAuthServerStorage contract. The Postgres adapter has its own
// integration test that requires a running database; this exercise is
// hermetic so it runs on every developer machine.

func TestMemoryOAuthClientLifecycle(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	c := theauth.OAuthClient{
		ID:                      ulid.New(),
		ClientID:                "client-abc",
		ClientName:              "MCP Files Client",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scope:                   "files.read",
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	}
	stored, err := s.InsertOAuthClient(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}
	got, err := s.OAuthClientByClientID(ctx, "client-abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientName != "MCP Files Client" {
		t.Fatalf("got name %q", got.ClientName)
	}
	got.ClientName = "renamed"
	updated, err := s.UpdateOAuthClient(ctx, *got)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ClientName != "renamed" {
		t.Fatalf("update did not persist: %+v", updated)
	}
	if err := s.DeleteOAuthClient(ctx, "client-abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OAuthClientByClientID(ctx, "client-abc"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemoryAuthorizationCodeAtomicConsume(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	c := theauth.AuthorizationCode{
		Code:                "code-xyz",
		ClientID:            "client-abc",
		UserID:              ulid.New(),
		RedirectURI:         "https://app.example.com/cb",
		Scope:               []string{"files.read"},
		Resource:            "https://files.example.com/mcp",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	if err := s.InsertAuthorizationCode(ctx, c); err != nil {
		t.Fatal(err)
	}
	// 100 concurrent consumers; exactly one wins.
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeAuthorizationCode(ctx, "code-xyz"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected exactly one winner, got %d", wins.Load())
	}
}

func TestMemoryRefreshTokenFamilyRevoke(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	familyID := ulid.New()
	for i := 0; i < 3; i++ {
		hash := []byte{byte(i), 1, 2, 3}
		if err := s.InsertRefreshToken(ctx, theauth.RefreshToken{
			ID:        ulid.New(),
			Hash:      hash,
			FamilyID:  familyID,
			ClientID:  "client-abc",
			Resource:  "https://files.example.com/mcp",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeRefreshTokenFamily(ctx, familyID, "reuse"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rt, err := s.RefreshTokenByHash(ctx, []byte{byte(i), 1, 2, 3})
		if err != nil {
			t.Fatal(err)
		}
		if rt.RevokedAt == nil {
			t.Fatalf("token %d should be revoked", i)
		}
	}
}

func TestMemoryJWKSStateMachine(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	k := theauth.JWKSKey{
		KID:        "kid-1",
		Alg:        "EdDSA",
		Use:        "sig",
		PublicJWK:  []byte("{}"),
		PrivateEnc: []byte("enc"),
		State:      theauth.JWKSStateNext,
	}
	if err := s.InsertJWKSKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	if err := s.UpdateJWKSKeyState(ctx, "kid-1", theauth.JWKSStateCurrent, at); err != nil {
		t.Fatal(err)
	}
	got, err := s.JWKSKeyByKID(ctx, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != theauth.JWKSStateCurrent {
		t.Fatalf("expected current, got %s", got.State)
	}
	if got.PromotedAt == nil {
		t.Fatal("expected PromotedAt to be set after promotion")
	}
}

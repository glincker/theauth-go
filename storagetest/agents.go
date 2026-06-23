package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testAgents(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	ownerUID := newID()

	makeAgent := func() theauth.Agent {
		return theauth.Agent{
			ID:          newID(),
			OwnerUserID: &ownerUID,
			Name:        "storagetest-agent-" + newID().String(),
			Status:      theauth.AgentStatusActive,
			ClientID:    "st-agent-client-" + newID().String(),
			CreatedAt:   time.Now(),
		}
	}

	var agentID theauth.ULID

	t.Run("Create", func(t *testing.T) {
		a := makeAgent()
		got, err := store.InsertAgent(ctx, a)
		if err != nil {
			t.Fatalf("InsertAgent: %v", err)
		}
		if got.Status != theauth.AgentStatusActive {
			t.Fatalf("Status: want active, got %q", got.Status)
		}
		agentID = got.ID
	})

	t.Run("FetchByID", func(t *testing.T) {
		got, err := store.AgentByID(ctx, agentID)
		if err != nil {
			t.Fatalf("AgentByID: %v", err)
		}
		if got.OwnerUserID == nil || *got.OwnerUserID != ownerUID {
			t.Fatal("OwnerUserID mismatch")
		}
	})

	t.Run("ListByOwner", func(t *testing.T) {
		// Create a second agent for the same owner.
		a2 := makeAgent()
		if _, err := store.InsertAgent(ctx, a2); err != nil {
			t.Fatalf("InsertAgent a2: %v", err)
		}

		agents, err := store.AgentsByOwner(ctx, theauth.AgentOwner{UserID: &ownerUID})
		if err != nil {
			t.Fatalf("AgentsByOwner: %v", err)
		}
		if len(agents) < 2 {
			t.Fatalf("expected at least 2 agents, got %d", len(agents))
		}
	})

	t.Run("Suspend", func(t *testing.T) {
		if err := store.UpdateAgentStatus(ctx, agentID, theauth.AgentStatusSuspended, time.Now()); err != nil {
			t.Fatalf("UpdateAgentStatus (suspend): %v", err)
		}
		got, err := store.AgentByID(ctx, agentID)
		if err != nil {
			t.Fatalf("AgentByID after suspend: %v", err)
		}
		if got.Status != theauth.AgentStatusSuspended {
			t.Fatalf("Status: want suspended, got %q", got.Status)
		}
	})

	t.Run("Resume", func(t *testing.T) {
		if err := store.UpdateAgentStatus(ctx, agentID, theauth.AgentStatusActive, time.Now()); err != nil {
			t.Fatalf("UpdateAgentStatus (resume): %v", err)
		}
		got, err := store.AgentByID(ctx, agentID)
		if err != nil {
			t.Fatalf("AgentByID after resume: %v", err)
		}
		if got.Status != theauth.AgentStatusActive {
			t.Fatalf("Status: want active, got %q", got.Status)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		if err := store.UpdateAgentStatus(ctx, agentID, theauth.AgentStatusRevoked, time.Now()); err != nil {
			t.Fatalf("UpdateAgentStatus (revoke): %v", err)
		}
		got, err := store.AgentByID(ctx, agentID)
		if err != nil {
			t.Fatalf("AgentByID after revoke: %v", err)
		}
		if got.Status != theauth.AgentStatusRevoked {
			t.Fatalf("Status: want revoked, got %q", got.Status)
		}
	})

	t.Run("AgentNotFound", func(t *testing.T) {
		if _, err := store.AgentByID(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateLastActive", func(t *testing.T) {
		a := makeAgent()
		inserted, err := store.InsertAgent(ctx, a)
		if err != nil {
			t.Fatalf("InsertAgent: %v", err)
		}
		now := time.Now()
		if err := store.UpdateAgentLastActive(ctx, inserted.ID, now); err != nil {
			t.Fatalf("UpdateAgentLastActive: %v", err)
		}
		got, err := store.AgentByID(ctx, inserted.ID)
		if err != nil {
			t.Fatalf("AgentByID: %v", err)
		}
		if got.LastActiveAt == nil {
			t.Fatal("LastActiveAt should be set after UpdateAgentLastActive")
		}
	})

	t.Run("AgentCredentials", func(t *testing.T) {
		a := makeAgent()
		inserted, err := store.InsertAgent(ctx, a)
		if err != nil {
			t.Fatalf("InsertAgent for cred test: %v", err)
		}

		credID := newID()
		cred := theauth.AgentCredential{
			ID:        credID,
			AgentID:   inserted.ID,
			Kind:      theauth.AgentCredentialKindSecret,
			ValueEnc:  []byte("hashed-secret"),
			CreatedAt: time.Now(),
		}
		if err := store.InsertAgentCredential(ctx, cred); err != nil {
			t.Fatalf("InsertAgentCredential: %v", err)
		}

		creds, err := store.AgentCredentialsByAgentID(ctx, inserted.ID)
		if err != nil {
			t.Fatalf("AgentCredentialsByAgentID: %v", err)
		}
		if len(creds) < 1 {
			t.Fatal("expected at least 1 credential")
		}

		if err := store.RevokeAgentCredential(ctx, credID, time.Now()); err != nil {
			t.Fatalf("RevokeAgentCredential: %v", err)
		}
		creds2, err := store.AgentCredentialsByAgentID(ctx, inserted.ID)
		if err != nil {
			t.Fatalf("AgentCredentialsByAgentID after revoke: %v", err)
		}
		for _, c := range creds2 {
			if c.ID == credID && c.RevokedAt == nil {
				t.Fatal("credential should have RevokedAt set after revoke")
			}
		}
	})
}

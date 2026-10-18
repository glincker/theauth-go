package storagetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// AgentSuiteStorage is the agent, agent credential and delegation subset of
// theauth.OAuthServerStorage, so adapters without the OAuth client, code and
// JWKS tables can still run the agent contract.
type AgentSuiteStorage interface {
	InsertAgent(ctx context.Context, a theauth.Agent) (theauth.Agent, error)
	AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error)
	AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error)
	UpdateAgentStatus(ctx context.Context, id theauth.ULID, status string, at time.Time) error
	UpdateAgentExpiry(ctx context.Context, id theauth.ULID, expiresAt *time.Time) error
	UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error
	InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id theauth.ULID, at time.Time) error
	UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error
}

// DelegationSuiteStorage is the delegation subset of theauth.OAuthServerStorage.
type DelegationSuiteStorage interface {
	InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error
}

// RunAgents runs the agent and agent credential contract, including
// concurrent status changes. Pass a store the contract may write to freely.
func RunAgents(t *testing.T, store AgentSuiteStorage) {
	t.Helper()
	ctx := context.Background()
	owner := newID()
	org := newID()
	mk := func() theauth.Agent {
		return theauth.Agent{
			ID: newID(), OwnerUserID: &owner, Name: "agent-" + newID().String(),
			ClientID: "agent-client-" + newID().String(), Scope: []string{"read", "write"},
		}
	}

	t.Run("InsertDefaultsAndRoundTrip", func(t *testing.T) {
		a := mk()
		got, err := store.InsertAgent(ctx, a)
		if err != nil {
			t.Fatalf("InsertAgent: %v", err)
		}
		if got.Status != theauth.AgentStatusActive || got.CreatedAt.IsZero() {
			t.Fatalf("defaults not applied: %+v", got)
		}
		read, err := store.AgentByID(ctx, a.ID)
		if err != nil {
			t.Fatalf("AgentByID: %v", err)
		}
		if read.ClientID != a.ClientID || len(read.Scope) != 2 || read.Scope[1] != "write" || read.OrganizationID != nil {
			t.Fatalf("round trip mismatch: %+v", read)
		}
		byClient, err := store.AgentByClientID(ctx, a.ClientID)
		if err != nil || byClient.ID != a.ID {
			t.Fatalf("AgentByClientID = %+v, %v", byClient, err)
		}
	})

	t.Run("ExpiresAtRoundTrip", func(t *testing.T) {
		exp := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Millisecond)
		a := mk()
		a.ExpiresAt = &exp
		got, err := store.InsertAgent(ctx, a)
		if err != nil {
			t.Fatalf("InsertAgent: %v", err)
		}
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
			t.Fatalf("insert result ExpiresAt = %v, want %v", got.ExpiresAt, exp)
		}
		read, err := store.AgentByID(ctx, a.ID)
		if err != nil || read.ExpiresAt == nil || !read.ExpiresAt.Equal(exp) {
			t.Fatalf("AgentByID ExpiresAt = %v, %v, want %v", read, err, exp)
		}
		byClient, err := store.AgentByClientID(ctx, a.ClientID)
		if err != nil || byClient.ExpiresAt == nil || !byClient.ExpiresAt.Equal(exp) {
			t.Fatalf("AgentByClientID ExpiresAt mismatch: %+v, %v", byClient, err)
		}
		listed, err := store.AgentsByOwner(ctx, theauth.AgentOwner{UserID: &owner})
		if err != nil {
			t.Fatalf("AgentsByOwner: %v", err)
		}
		var seen bool
		for _, l := range listed {
			if l.ID == a.ID {
				seen = true
				if l.ExpiresAt == nil || !l.ExpiresAt.Equal(exp) {
					t.Fatalf("AgentsByOwner ExpiresAt = %v, want %v", l.ExpiresAt, exp)
				}
			}
		}
		if !seen {
			t.Fatal("agent missing from owner listing")
		}
	})

	t.Run("ExpiresAtDefaultsToNil", func(t *testing.T) {
		a := mk()
		if _, err := store.InsertAgent(ctx, a); err != nil {
			t.Fatal(err)
		}
		read, err := store.AgentByID(ctx, a.ID)
		if err != nil || read.ExpiresAt != nil {
			t.Fatalf("ExpiresAt = %v, %v, want nil", read, err)
		}
	})

	t.Run("UpdateAgentExpiry", func(t *testing.T) {
		a := mk()
		if _, err := store.InsertAgent(ctx, a); err != nil {
			t.Fatal(err)
		}
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
		if err := store.UpdateAgentExpiry(ctx, a.ID, &exp); err != nil {
			t.Fatalf("UpdateAgentExpiry set: %v", err)
		}
		read, err := store.AgentByID(ctx, a.ID)
		if err != nil || read.ExpiresAt == nil || !read.ExpiresAt.Equal(exp) {
			t.Fatalf("after set ExpiresAt = %v, %v, want %v", read, err, exp)
		}
		if err := store.UpdateAgentExpiry(ctx, a.ID, nil); err != nil {
			t.Fatalf("UpdateAgentExpiry clear: %v", err)
		}
		read, err = store.AgentByID(ctx, a.ID)
		if err != nil || read.ExpiresAt != nil {
			t.Fatalf("after clear ExpiresAt = %v, %v, want nil", read, err)
		}
		if err := store.UpdateAgentExpiry(ctx, newID(), &exp); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UpdateAgentExpiry unknown agent: want ErrNotFound, got %v", err)
		}
	})

	t.Run("DuplicateClientIDRejected", func(t *testing.T) {
		a := mk()
		if _, err := store.InsertAgent(ctx, a); err != nil {
			t.Fatal(err)
		}
		b := mk()
		b.ClientID = a.ClientID
		if _, err := store.InsertAgent(ctx, b); err == nil {
			t.Fatal("duplicate client_id must be rejected")
		}
	})

	t.Run("MissingLookups", func(t *testing.T) {
		if _, err := store.AgentByID(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("AgentByID: want ErrNotFound, got %v", err)
		}
		if _, err := store.AgentByClientID(ctx, "no-such-client"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("AgentByClientID: want ErrNotFound, got %v", err)
		}
		if err := store.UpdateAgentStatus(ctx, newID(), theauth.AgentStatusSuspended, time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UpdateAgentStatus: want ErrNotFound, got %v", err)
		}
		if err := store.UpdateAgentLastActive(ctx, newID(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UpdateAgentLastActive: want ErrNotFound, got %v", err)
		}
	})

	t.Run("OwnerListing", func(t *testing.T) {
		o := newID()
		for i := 0; i < 2; i++ {
			a := mk()
			a.OwnerUserID = &o
			if _, err := store.InsertAgent(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
		svc := mk()
		svc.OwnerUserID, svc.OrganizationID = nil, &org
		if _, err := store.InsertAgent(ctx, svc); err != nil {
			t.Fatalf("org-owned InsertAgent: %v", err)
		}
		byUser, err := store.AgentsByOwner(ctx, theauth.AgentOwner{UserID: &o})
		if err != nil || len(byUser) != 2 {
			t.Fatalf("by user = %d, %v", len(byUser), err)
		}
		byOrg, err := store.AgentsByOwner(ctx, theauth.AgentOwner{OrganizationID: &org})
		if err != nil || len(byOrg) != 1 || byOrg[0].OrganizationID == nil || byOrg[0].OwnerUserID != nil {
			t.Fatalf("by org = %+v, %v", byOrg, err)
		}
		// SQL adapters reject an empty owner; memory returns nothing. Either
		// way no agent may leak.
		if none, err := store.AgentsByOwner(ctx, theauth.AgentOwner{}); err == nil && len(none) != 0 {
			t.Fatalf("empty owner returned %d agents", len(none))
		}
	})

	t.Run("StatusTransitionsAndLastActive", func(t *testing.T) {
		a, err := store.InsertAgent(ctx, mk())
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range []string{theauth.AgentStatusSuspended, theauth.AgentStatusActive, theauth.AgentStatusRevoked, theauth.AgentStatusRevoked} {
			if err := store.UpdateAgentStatus(ctx, a.ID, st, time.Now()); err != nil {
				t.Fatalf("UpdateAgentStatus(%s): %v", st, err)
			}
			got, _ := store.AgentByID(ctx, a.ID)
			if got.Status != st {
				t.Fatalf("status = %q, want %q", got.Status, st)
			}
		}
		at := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
		if err := store.UpdateAgentLastActive(ctx, a.ID, at); err != nil {
			t.Fatal(err)
		}
		got, _ := store.AgentByID(ctx, a.ID)
		if got.LastActiveAt == nil || !got.LastActiveAt.Equal(at) {
			t.Fatalf("LastActiveAt = %v, want %v", got.LastActiveAt, at)
		}
	})

	t.Run("ConcurrentStatusChanges", func(t *testing.T) {
		a, err := store.InsertAgent(ctx, mk())
		if err != nil {
			t.Fatal(err)
		}
		statuses := []string{theauth.AgentStatusActive, theauth.AgentStatusSuspended, theauth.AgentStatusRevoked}
		var wg sync.WaitGroup
		var failures atomic.Int32
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if err := store.UpdateAgentStatus(ctx, a.ID, statuses[i%3], time.Now()); err != nil {
					failures.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if failures.Load() != 0 {
			t.Fatalf("%d concurrent status updates failed", failures.Load())
		}
		got, err := store.AgentByID(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		switch got.Status {
		case theauth.AgentStatusActive, theauth.AgentStatusSuspended, theauth.AgentStatusRevoked:
		default:
			t.Fatalf("torn status %q", got.Status)
		}
	})

	t.Run("Credentials", func(t *testing.T) {
		a, err := store.InsertAgent(ctx, mk())
		if err != nil {
			t.Fatal(err)
		}
		c1 := theauth.AgentCredential{ID: newID(), AgentID: a.ID, Kind: theauth.AgentCredentialKindSecret, ValueEnc: []byte("hash-1"), CreatedAt: time.Now().Add(-time.Second)}
		c2 := theauth.AgentCredential{ID: newID(), AgentID: a.ID, Kind: theauth.AgentCredentialKindSecret, ValueEnc: []byte("hash-2"), CreatedAt: time.Now()}
		for _, c := range []theauth.AgentCredential{c2, c1} {
			if err := store.InsertAgentCredential(ctx, c); err != nil {
				t.Fatalf("InsertAgentCredential: %v", err)
			}
		}
		list, err := store.AgentCredentialsByAgentID(ctx, a.ID)
		if err != nil || len(list) != 2 || list[0].ID != c1.ID || string(list[0].ValueEnc) != "hash-1" {
			t.Fatalf("list = %+v, %v", list, err)
		}
		used := time.Now().Truncate(time.Millisecond)
		if err := store.UpdateAgentCredentialLastUsed(ctx, c1.ID, used); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeAgentCredential(ctx, c1.ID, time.Now()); err != nil {
			t.Fatalf("RevokeAgentCredential: %v", err)
		}
		// A repeat revoke may report ErrNotFound (SQL adapters) or succeed
		// (memory); it must not fail any other way.
		if err := store.RevokeAgentCredential(ctx, c1.ID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second revoke: %v", err)
		}
		list, _ = store.AgentCredentialsByAgentID(ctx, a.ID)
		for _, c := range list {
			switch c.ID {
			case c1.ID:
				if c.RevokedAt == nil || c.LastUsedAt == nil || !c.LastUsedAt.Equal(used) {
					t.Fatalf("c1 state wrong: %+v", c)
				}
			case c2.ID:
				if c.RevokedAt != nil {
					t.Fatal("c2 must stay live")
				}
			}
		}
		if err := store.RevokeAgentCredential(ctx, newID(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("revoke missing: want ErrNotFound, got %v", err)
		}
	})
}

// RunDelegations runs the delegation grant contract, including the live-tuple
// rule and concurrent revoke (exactly one winner).
func RunDelegations(t *testing.T, store DelegationSuiteStorage) {
	t.Helper()
	ctx := context.Background()
	mk := func(u, a theauth.ULID, res string) theauth.DelegationGrant {
		return theauth.DelegationGrant{ID: newID(), UserID: u, AgentID: a, Scope: []string{"read"}, Resource: res, MaxDurationSeconds: 600}
	}

	t.Run("RoundTripAndLists", func(t *testing.T) {
		u, a, org := newID(), newID(), newID()
		exp := time.Now().Add(time.Hour).Truncate(time.Millisecond)
		g := mk(u, a, "https://r1.example")
		g.OrganizationID, g.ExpiresAt = &org, &exp
		if _, err := store.InsertDelegationGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
		if _, err := store.InsertDelegationGrant(ctx, mk(u, a, "https://r2.example")); err != nil {
			t.Fatal(err)
		}
		got, err := store.DelegationGrantByID(ctx, g.ID)
		if err != nil || got.OrganizationID == nil || *got.OrganizationID != org || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.MaxDurationSeconds != 600 || got.CreatedAt.IsZero() {
			t.Fatalf("round trip = %+v, %v", got, err)
		}
		byUser, _ := store.DelegationGrantsByUserID(ctx, u)
		byAgent, _ := store.DelegationGrantsByAgentID(ctx, a)
		if len(byUser) != 2 || len(byAgent) != 2 {
			t.Fatalf("lists = %d, %d", len(byUser), len(byAgent))
		}
	})

	t.Run("LiveTupleUnique", func(t *testing.T) {
		u, a := newID(), newID()
		if _, err := store.InsertDelegationGrant(ctx, mk(u, a, "https://r.example")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.InsertDelegationGrant(ctx, mk(u, a, "https://r.example")); err == nil {
			t.Fatal("second live grant for the same tuple must be rejected")
		}
	})

	t.Run("TupleLookupPrefersLive", func(t *testing.T) {
		u, a := newID(), newID()
		old := mk(u, a, "https://r.example")
		if _, err := store.InsertDelegationGrant(ctx, old); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeDelegationGrant(ctx, old.ID, time.Now(), "old"); err != nil {
			t.Fatal(err)
		}
		if got, err := store.DelegationGrantByUserAgentResource(ctx, u, a, "https://r.example"); err != nil || got.ID != old.ID || got.RevokedAt == nil {
			t.Fatalf("revoked-only lookup = %+v, %v", got, err)
		}
		fresh := mk(u, a, "https://r.example")
		if _, err := store.InsertDelegationGrant(ctx, fresh); err != nil {
			t.Fatalf("replace after revoke: %v", err)
		}
		if got, err := store.DelegationGrantByUserAgentResource(ctx, u, a, "https://r.example"); err != nil || got.ID != fresh.ID || got.RevokedAt != nil {
			t.Fatalf("live lookup = %+v, %v", got, err)
		}
	})

	t.Run("RevokeIsConditional", func(t *testing.T) {
		g := mk(newID(), newID(), "https://r.example")
		if _, err := store.InsertDelegationGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
		first := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
		if err := store.RevokeDelegationGrant(ctx, g.ID, first, "first"); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeDelegationGrant(ctx, g.ID, time.Now(), "second"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second revoke: want ErrNotFound, got %v", err)
		}
		got, _ := store.DelegationGrantByID(ctx, g.ID)
		if got.RevocationNote != "first" || got.RevokedAt == nil || !got.RevokedAt.Equal(first) {
			t.Fatalf("second revoke changed state: %+v", got)
		}
		if err := store.RevokeDelegationGrant(ctx, newID(), time.Now(), "x"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("revoke missing: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ConcurrentRevokeSingleWinner", func(t *testing.T) {
		g := mk(newID(), newID(), "https://r.example")
		if _, err := store.InsertDelegationGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
		var wins, notFound, other atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch err := store.RevokeDelegationGrant(ctx, g.ID, time.Now(), "race"); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, storage.ErrNotFound):
					notFound.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || notFound.Load() != 15 || other.Load() != 0 {
			t.Fatalf("wins=%d notFound=%d other=%d, want 1/15/0", wins.Load(), notFound.Load(), other.Load())
		}
	})

	t.Run("ConcurrentInsertSingleWinner", func(t *testing.T) {
		u, a := newID(), newID()
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.InsertDelegationGrant(ctx, mk(u, a, "https://race.example")); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("insert winners = %d, want 1", wins.Load())
		}
	})

	t.Run("Missing", func(t *testing.T) {
		if _, err := store.DelegationGrantByID(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		if _, err := store.DelegationGrantByUserAgentResource(ctx, newID(), newID(), "x"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}

// RunJWTBearer runs the RFC 7523 jti replay cache contract.
func RunJWTBearer(t *testing.T, store theauth.JWTBearerStorage) {
	t.Helper()
	ctx := context.Background()

	t.Run("ReplayDetected", func(t *testing.T) {
		jti := "jti-" + newID().String()
		if err := store.InsertJTI(ctx, jti, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := store.InsertJTI(ctx, jti, time.Now().Add(time.Hour)); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("replay: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpiredJTIReusable", func(t *testing.T) {
		jti := "jti-" + newID().String()
		if err := store.InsertJTI(ctx, jti, time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := store.InsertJTI(ctx, jti, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("reuse after expiry: %v", err)
		}
	})

	t.Run("SweepKeepsLive", func(t *testing.T) {
		live, dead := "live-"+newID().String(), "dead-"+newID().String()
		if err := store.InsertJTI(ctx, live, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := store.InsertJTI(ctx, dead, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := store.SweepExpiredJTIs(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := store.InsertJTI(ctx, live, time.Now().Add(time.Hour)); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("live jti must survive sweep, got %v", err)
		}
		if err := store.SweepExpiredJTIs(ctx, time.Now()); err != nil {
			t.Fatalf("idempotent sweep: %v", err)
		}
	})

	t.Run("ConcurrentSameJTISingleWinner", func(t *testing.T) {
		jti := "race-" + newID().String()
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := store.InsertJTI(ctx, jti, time.Now().Add(time.Hour)); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("winners = %d, want 1", wins.Load())
		}
	})
}

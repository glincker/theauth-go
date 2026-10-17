package sqlite_test

import (
	"context"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func openAgentStore(t *testing.T, opts ...sqlitestore.Option) *sqlitestore.Store {
	t.Helper()
	return newStore(t, opts...)
}

func TestAgentContracts(t *testing.T) {
	t.Parallel()
	suites := []struct {
		name string
		run  func(t *testing.T, s *sqlitestore.Store)
	}{
		{"Agents", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunAgents(t, s) }},
		{"Delegations", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunDelegations(t, s) }},
		{"JWTBearer", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunJWTBearer(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, openAgentStore(t))
		})
		t.Run(tc.name+"CustomPrefix", func(t *testing.T) {
			t.Parallel()
			tc.run(t, openAgentStore(t, sqlitestore.WithTablePrefix("auth_x_")))
		})
	}

	t.Run("ASStorageSubset", func(t *testing.T) {
		t.Parallel()
		s := openAgentStore(t)
		var _ storagetest.AgentSuiteStorage = s
		var _ storagetest.DelegationSuiteStorage = s
		var _ theauth.JWTBearerStorage = s
		ctx := context.Background()
		owner := newID()
		a, err := s.InsertAgent(ctx, theauth.Agent{ID: newID(), OwnerUserID: &owner, Name: "n", ClientID: "c-1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateAgentLastActive(ctx, a.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CredentialRevokeKeepsFirstTime", func(t *testing.T) {
		t.Parallel()
		s := openAgentStore(t)
		ctx := context.Background()
		owner := newID()
		a, err := s.InsertAgent(ctx, theauth.Agent{ID: newID(), OwnerUserID: &owner, Name: "n", ClientID: "c-2"})
		if err != nil {
			t.Fatal(err)
		}
		c := theauth.AgentCredential{ID: newID(), AgentID: a.ID, Kind: theauth.AgentCredentialKindSecret, ValueEnc: []byte("h")}
		if err := s.InsertAgentCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
		first := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
		if err := s.RevokeAgentCredential(ctx, c.ID, first); err != nil {
			t.Fatal(err)
		}
		_ = s.RevokeAgentCredential(ctx, c.ID, time.Now())
		list, err := s.AgentCredentialsByAgentID(ctx, a.ID)
		if err != nil || len(list) != 1 || list[0].RevokedAt == nil || !list[0].RevokedAt.Equal(first) {
			t.Fatalf("revoked_at moved: %+v, %v", list, err)
		}
	})
}

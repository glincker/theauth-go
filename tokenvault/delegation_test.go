package tokenvault_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/glincker/theauth-go/v2/tokenvault"
	"github.com/oklog/ulid/v2"
)

func TestGrantDelegations(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	user := ulid.MustNew(ulid.Now(), rand.Reader)
	agent := ulid.MustNew(ulid.Now(), rand.Reader)
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	mk := func(provider string, scope []string, exp *time.Time) {
		t.Helper()
		_, err := store.InsertDelegationGrant(ctx, theauth.DelegationGrant{
			ID: ulid.MustNew(ulid.Now(), rand.Reader), UserID: user, AgentID: agent,
			Resource: tokenvault.Resource(provider), Scope: scope, ExpiresAt: exp, CreatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mk("ok", []string{"read", "write"}, &future)
	mk("expired", []string{"read"}, &past)
	mk("revoked", []string{"read"}, nil)
	g, _ := store.DelegationGrantByUserAgentResource(ctx, user, agent, tokenvault.Resource("revoked"))
	if err := store.RevokeDelegationGrant(ctx, g.ID, now, "test"); err != nil {
		t.Fatal(err)
	}

	d := tokenvault.GrantDelegations{Store: store}
	tests := []struct {
		name     string
		user     string
		agent    string
		provider string
		scopes   []string
		want     bool
	}{
		{"granted", user.String(), agent.String(), "ok", []string{"read"}, true},
		{"scope superset", user.String(), agent.String(), "ok", []string{"read", "admin"}, false},
		{"expired", user.String(), agent.String(), "expired", []string{"read"}, false},
		{"revoked", user.String(), agent.String(), "revoked", []string{"read"}, false},
		{"no grant", user.String(), agent.String(), "other", []string{"read"}, false},
		{"other user", ulid.MustNew(ulid.Now(), rand.Reader).String(), agent.String(), "ok", []string{"read"}, false},
		{"not a ulid", "alice", agent.String(), "ok", []string{"read"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.Allows(ctx, tc.user, tc.agent, tc.provider, tc.scopes, now)
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v want %v", got, err, tc.want)
			}
		})
	}
}

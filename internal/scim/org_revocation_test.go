package scim_test

import (
	"context"
	"sync"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/revocation"
	"github.com/glincker/theauth-go/v2/internal/theauthtest"
)

// TestSCIM_OrgOnlyDeactivationFiresOrgScopedEvent covers a multi-org user
// removed from one organization: the user stays enabled, so no owner event
// fires, but watchers scoped to that organization and user must be cut.
func TestSCIM_OrgOnlyDeactivationFiresOrgScopedEvent(t *testing.T) {
	a, store, orgA, token, srv := newSCIMTestStack(t)
	ctx := context.Background()
	uid, _ := scimUserWithSession(t, store, srv, token, "orgwatch@acme.test")
	user, err := store.UserByEmail(ctx, "orgwatch@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	owner := theauthtest.NewUser(t, store, "orgwatch-owner@x.test")
	orgB, err := a.CreateOrganization(ctx, "Beta", "beta-w", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{
		OrganizationID: orgB.ID, UserID: user.ID, Role: "member", JoinedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []theauth.RevocationEvent
	unsub, err := a.SubscribeRevocations(func(ev theauth.RevocationEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()
	inA, cancelA := a.WatchRevocation(ctx, theauth.RevocationTarget{UserID: user.ID.String(), OrganizationID: orgA.ID.String()}, theauth.WatchOptions{})
	defer cancelA(nil)
	inB, cancelB := a.WatchRevocation(ctx, theauth.RevocationTarget{UserID: user.ID.String(), OrganizationID: orgB.ID.String()}, theauth.WatchOptions{})
	defer cancelB(nil)

	r := scimReq(t, srv, "DELETE", "/scim/v2/Users/"+uid, token, nil)
	_ = r.Body.Close()

	select {
	case <-inA.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("stream scoped to the deprovisioning organization still open")
	}
	if inB.Err() != nil {
		t.Fatal("stream scoped to the user's other organization was cut")
	}
	st, err := store.AccountStateByUserID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.DisabledAt != nil {
		t.Fatal("multi-org user must not be disabled")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, ev := range got {
		if ev.Kind == revocation.Owner {
			t.Fatalf("owner event fired for a multi-org user: %+v", ev)
		}
	}
}

package shrink

import (
	"context"
	"fmt"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
	oklog "github.com/oklog/ulid/v2"
)

func newID(at time.Time, n uint64) theauth.ULID {
	var entropy [10]byte
	entropy[9] = byte(n)
	entropy[8] = byte(n >> 8)
	id := oklog.ULID{}
	_ = id.SetTime(oklog.Timestamp(at))
	_ = id.SetEntropy(entropy[:])
	return id
}

func TestAuditRowsAdapter(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	agent, other := "agent-1", "agent-2"
	var events []theauth.AuditEvent
	for i := 0; i < 30; i++ {
		who := agent
		if i%3 == 0 {
			who = other
		}
		at := t0.Add(time.Duration(i) * time.Second)
		res, reason := ResultAllowed, ""
		if i%5 == 0 {
			res, reason = ResultDenied, noGrant
		}
		events = append(events, DecisionEvent(newID(at, uint64(i)), who, "read", fmt.Sprintf("doc:%d", i%4), res, reason, at, nil))
	}
	events = append(events, theauth.AuditEvent{ID: newID(t0, 99), Action: "login", ActorID: agent, CreatedAt: t0})
	if err := store.InsertAuditEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	src := AuditRows{Store: store}
	a, err := AnalyzeUsage(ctx, StaticGrants{own("read", "doc:*")}, src, agent, AnalyzeOptions{PageSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	// Agent rows are i not divisible by 3: 20 of 30. Of those, i%5==0 and i%3!=0: 5,10,20,25 are denied.
	if a.Evidence.RowsScanned != 20 || a.Evidence.NoGrantDenials != 4 || a.Evidence.AllowedRows != 16 {
		t.Fatalf("evidence = %+v", a.Evidence)
	}
	p, err := PreviewPolicyChange(ctx, src, agent, []Permission{perm("read", "doc:0")}, PreviewOptions{PageSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	if p.RowsScanned != 20 || p.NewlyDeniedCount == 0 {
		t.Fatalf("preview = %+v", p)
	}
}

func TestStorageGrants(t *testing.T) {
	ctx := context.Background()
	agentID := newID(t0, 1)
	now := t0
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	store := memory.New()
	for i, g := range []theauth.DelegationGrant{
		{ID: newID(t0, 10), AgentID: agentID, Scope: []string{"read", "write"}, Resource: "https://api.example/a"},
		{ID: newID(t0, 11), AgentID: agentID, Scope: []string{"read"}, Resource: "https://api.example/b", ExpiresAt: &past},
		{ID: newID(t0, 12), AgentID: agentID, Scope: []string{"read"}, Resource: "https://api.example/c", RevokedAt: &past},
		{ID: newID(t0, 13), AgentID: agentID, Scope: []string{"read"}, Resource: "https://api.example/d", ExpiresAt: &future},
	} {
		g.UserID = newID(t0, 50)
		g.CreatedAt = past
		if _, err := store.InsertDelegationGrant(ctx, g); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	pols := func(context.Context, string) ([]*policy.Policy, error) {
		p, err := policy.Parse([]byte(`{"version":"1","id":"p","statements":[{"effect":"allow","actions":["execute"],"resources":["tool:x"]}]}`))
		return []*policy.Policy{p}, err
	}
	gs, err := StorageGrants{Policies: pols, Delegations: store}.Grants(ctx, agentID.String(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 4 || gs[0].Source.Kind != SourceOwn || gs[1].Source.Kind != SourceDelegation {
		t.Fatalf("grants = %+v", gs)
	}
	for _, g := range gs[1:] {
		if g.Permission.Resource == "https://api.example/b" || g.Permission.Resource == "https://api.example/c" {
			t.Fatalf("inactive grant leaked: %+v", g)
		}
	}
	if _, err := (StorageGrants{Delegations: store}).Grants(ctx, "not-a-ulid", now); err == nil {
		t.Fatal("want parse error")
	}
}

package agentpolicy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"

	"github.com/glincker/theauth-go/v2/agentpolicy"
	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

func doc(id string, st ...policy.Statement) policy.Policy {
	return policy.Policy{Version: policy.Version, ID: id, Statements: st}
}

func TestEngineDecide(t *testing.T) {
	allow := policy.Statement{Effect: policy.Allow, Actions: []string{"files.*"}, Resources: []string{"*"}}
	deny := policy.Statement{ID: "d", Effect: policy.Deny, Actions: []string{"files.delete"}, Resources: []string{"*"}}
	e, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{doc("b", allow), doc("a", deny)}})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := e.Decide(context.Background(), models.Agent{ID: ulid.New()}, []agent.PolicyQuery{
		{Action: "files.read", Resource: "r"}, {Action: "files.delete", Resource: "r"}, {Action: "mail.send", Resource: "r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{agent.VerdictAllow, agent.VerdictDeny, agent.VerdictNone}
	for i, w := range want {
		if dec.Verdicts[i].Effect != w {
			t.Fatalf("verdict %d: %s want %s", i, dec.Verdicts[i].Effect, w)
		}
	}
	if !dec.Applies || dec.DenyList || len(dec.IDs) != 2 || dec.IDs[0] != "a" || len(dec.Hash) != 64 {
		t.Fatalf("decision meta: %+v", dec)
	}
	empty, _ := agentpolicy.New(agentpolicy.Config{})
	if d, _ := empty.Decide(context.Background(), models.Agent{}, nil); d.Applies {
		t.Fatal("no policies must not apply")
	}
}

func TestEngineRejectsInvalid(t *testing.T) {
	if _, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{{Version: "9"}}}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	e, _ := agentpolicy.New(agentpolicy.Config{Resolver: func(context.Context, models.Agent) ([]policy.Policy, error) {
		return []policy.Policy{{Version: "9"}}, nil
	}})
	if _, err := e.Decide(context.Background(), models.Agent{}, nil); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("resolver doc must be validated: %v", err)
	}
}

func TestModeAllowListRequiresAllow(t *testing.T) {
	denyOnly := doc("d", policy.Statement{Effect: policy.Deny, Actions: []string{"x"}, Resources: []string{"*"}})
	// Static deny only policy in allow list mode is a configuration error.
	if _, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{denyOnly}}); !errors.Is(err, agentpolicy.ErrNoAllowStatement) {
		t.Fatalf("want ErrNoAllowStatement, got %v", err)
	}
	// Deny list mode accepts it and passes unmatched actions.
	e, err := agentpolicy.New(agentpolicy.Config{Mode: agentpolicy.DenyList, Policies: []policy.Policy{denyOnly}})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := e.Decide(context.Background(), models.Agent{ID: ulid.New()}, []agent.PolicyQuery{{Action: "y", Resource: "r"}})
	if err != nil || !dec.DenyList || dec.Verdicts[0].Effect != agent.VerdictNone {
		t.Fatalf("deny list: %+v %v", dec, err)
	}
	// With a resolver the static set is allowed at New, but a resolved set with
	// no allow fails at evaluation, with a class.
	e2, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{denyOnly}, Resolver: func(context.Context, models.Agent) ([]policy.Policy, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e2.Decide(context.Background(), models.Agent{ID: ulid.New()}, nil)
	var ce *agent.ClassifiedError
	if !errors.Is(err, agentpolicy.ErrNoAllowStatement) || !errors.As(err, &ce) || ce.Class != agent.ErrClassNoAllow {
		t.Fatalf("want classed ErrNoAllowStatement, got %v", err)
	}
}

func TestResolverV2WinsAndValidatesLimit(t *testing.T) {
	allow := policy.Statement{Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"*"}}
	oldCalled := false
	rl := &theauth.AgentRateLimit{Requests: 3, Per: time.Hour}
	e, err := agentpolicy.New(agentpolicy.Config{
		Resolver: func(context.Context, models.Agent) ([]policy.Policy, error) { oldCalled = true; return nil, nil },
		ResolverV2: func(context.Context, models.Agent) (agentpolicy.Resolution, error) {
			return agentpolicy.Resolution{Policies: []policy.Policy{doc("v2", allow)}, RateLimit: rl}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := e.Decide(context.Background(), models.Agent{ID: ulid.New()}, []agent.PolicyQuery{{Action: "a", Resource: "r"}})
	if err != nil || oldCalled || dec.IDs[0] != "v2" || dec.RateLimit == nil || dec.RateLimit.Requests != 3 || dec.RateLimit.Burst != 3 {
		t.Fatalf("v2 must win: %+v old=%v err=%v", dec, oldCalled, err)
	}
	for _, bad := range []*theauth.AgentRateLimit{{}, {Requests: -1}, {Requests: 1, Per: -time.Second}} {
		bad := bad
		eb, _ := agentpolicy.New(agentpolicy.Config{ResolverV2: func(context.Context, models.Agent) (agentpolicy.Resolution, error) {
			return agentpolicy.Resolution{Policies: []policy.Policy{doc("v2", allow)}, RateLimit: bad}, nil
		}})
		_, err := eb.Decide(context.Background(), models.Agent{ID: ulid.New()}, nil)
		var ce *agent.ClassifiedError
		if !errors.Is(err, agentpolicy.ErrInvalidRateLimit) || !errors.As(err, &ce) || ce.Class != agent.ErrClassInvalidLimit {
			t.Fatalf("%+v: want ErrInvalidRateLimit, got %v", bad, err)
		}
	}
}

func TestResourceMatchingPathMode(t *testing.T) {
	allow := policy.Statement{Effect: policy.Allow, Actions: []string{"publish"}, Resources: []string{"ros2:/fleet/*/cmd"}}
	queries := []agent.PolicyQuery{
		{Action: "publish", Resource: "ros2:/fleet/a/cmd"},
		{Action: "publish", Resource: "ros2:/fleet/a/b/cmd"},
		{Action: "publish", Resource: "ros2:/fleet/../cmd"},
	}
	run := func(m pathmatch.Mode) []string {
		e, err := agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{doc("p", allow)}, ResourceMatching: m})
		if err != nil {
			t.Fatal(err)
		}
		dec, err := e.Decide(context.Background(), models.Agent{ID: ulid.New()}, queries)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(dec.Verdicts))
		for i, v := range dec.Verdicts {
			out[i] = v.Effect
		}
		return out
	}
	// Default keeps the policy package glob, where * crosses segments.
	for i, got := range run("") {
		want := agent.VerdictNone
		if policy.Match("ros2:/fleet/*/cmd", queries[i].Resource) {
			want = agent.VerdictAllow
		}
		if got != want {
			t.Fatalf("default query %d: %s want %s", i, got, want)
		}
	}
	if run("")[1] != agent.VerdictAllow {
		t.Fatal("default glob should still let * span segments (path mode narrows this)")
	}
	got := run(pathmatch.Path)
	want := []string{agent.VerdictAllow, agent.VerdictNone, agent.VerdictNone}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path query %d: %s want %s", i, got[i], want[i])
		}
	}
}

package agentpolicy_test

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go/v2/agentpolicy"
	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

func benchPolicies() []policy.Policy {
	return []policy.Policy{
		doc("fleet-deny", policy.Statement{ID: "no-admin", Effect: policy.Deny, Actions: []string{"admin.*"}, Resources: []string{"*"}}),
		doc("agent",
			policy.Statement{Effect: policy.Allow, Actions: []string{"files.read", "files.list"}, Resources: []string{"fs:/data/**", "fs:/shared/*"}},
			policy.Statement{Effect: policy.Allow, Actions: []string{"mail.send"}, Resources: []string{"mail:outbox:{agent_id}"}},
			policy.Statement{Effect: policy.Allow, Actions: []string{"tools.*"}, Resources: []string{"tool:search:*", "tool:calc:*"}},
		),
	}
}

func benchDecide(b *testing.B, mode pathmatch.Mode, queries []agent.PolicyQuery) {
	b.Helper()
	e, err := agentpolicy.New(agentpolicy.Config{Policies: benchPolicies(), ResourceMatching: mode})
	if err != nil {
		b.Fatal(err)
	}
	ag := models.Agent{ID: ulid.New(), ClientID: "client-1"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := e.Decide(ctx, ag, queries)
		if err != nil || !d.Applies {
			b.Fatal(err)
		}
	}
}

func benchQueries() []agent.PolicyQuery {
	return []agent.PolicyQuery{
		{Action: "files.read", Resource: "fs:/data/a/b.txt"},
		{Action: "files.list", Resource: "fs:/shared/x"},
		{Action: "tools.run", Resource: "tool:search:web"},
		{Action: "admin.reset", Resource: "fs:/data/a"},
		{Action: "mail.send", Resource: "mail:outbox:other"},
	}
}

// BenchmarkDecideDefault is one mint time Decide over five queries with the default matcher.
func BenchmarkDecideDefault(b *testing.B) { benchDecide(b, "", benchQueries()) }

// BenchmarkDecidePathMode is the same with the opt in path matcher.
func BenchmarkDecidePathMode(b *testing.B) { benchDecide(b, pathmatch.Path, benchQueries()) }

// BenchmarkDecideSingleQuery is the common one query call.
func BenchmarkDecideSingleQuery(b *testing.B) {
	benchDecide(b, "", benchQueries()[:1])
}

// BenchmarkDecideResolver adds a per agent resolver, which is re validated on every call.
func BenchmarkDecideResolver(b *testing.B) {
	e, err := agentpolicy.New(agentpolicy.Config{
		Policies: benchPolicies()[:1],
		Resolver: func(context.Context, models.Agent) ([]policy.Policy, error) { return benchPolicies()[1:], nil },
		Mode:     agentpolicy.DenyList,
	})
	if err != nil {
		b.Fatal(err)
	}
	ag := models.Agent{ID: ulid.New(), ClientID: "client-1"}
	q := benchQueries()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Decide(ctx, ag, q); err != nil {
			b.Fatal(err)
		}
	}
}

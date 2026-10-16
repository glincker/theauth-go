// Policy shrink demo. Runs in memory, no database and no network.
//
// It gives one agent a broad policy, sends a deterministic mix of calls through
// a toolguard.Guard that records every decision as an audit event, then asks
// what the agent actually used, proposes a smaller policy and replays the
// recorded decisions against it.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	oklog "github.com/oklog/ulid/v2"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/shrink"
	"github.com/glincker/theauth-go/v2/policy/toolguard"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const agentID = "agent_support_bot"

const doc = `{"version":"1","id":"support-bot","statements":[
 {"effect":"allow","actions":["read","write"],"resources":["mcp:github:repos"]},
 {"effect":"allow","actions":["read","write"],"resources":["mcp:github:issues"]},
 {"effect":"allow","actions":["read"],"resources":["mcp:github:pulls"]},
 {"effect":"allow","actions":["query"],"resources":["tool:db:orders"]},
 {"effect":"allow","actions":["query","delete"],"resources":["tool:db:users"]},
 {"effect":"allow","actions":["send"],"resources":["tool:mail"]},
 {"effect":"allow","actions":["*"],"resources":["tool:billing"]}]}`

func main() {
	ctx := context.Background()
	pol, err := policy.Parse([]byte(doc))
	if err != nil {
		log.Fatal(err)
	}
	loadPolicies := func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{pol}, nil }

	store := memory.New()
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	var n uint64
	guard := &toolguard.Guard{
		Policies: loadPolicies,
		OnDecision: func(c toolguard.Call, d policy.Decision) {
			n++
			at := base.Add(time.Duration(n) * time.Second)
			id := oklog.ULID{}
			_ = id.SetTime(oklog.Timestamp(at))
			_ = id.SetEntropy([]byte{0, 0, 0, 0, 0, 0, 0, byte(n >> 16), byte(n >> 8), byte(n)})
			ev := shrink.DecisionEvent(id, c.AgentID, c.Action, c.Resource, shrink.ResultOf(d), d.Reason, at, nil)
			if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{ev}); err != nil {
				log.Fatal(err)
			}
		},
	}

	// A deterministic call log: action, resource, how many times.
	traffic := []struct {
		action, resource string
		times            int
	}{
		{"read", "mcp:github:repos", 212},
		{"read", "mcp:github:issues", 148},
		{"write", "mcp:github:issues", 37},
		{"query", "tool:db:orders", 96},
		{"query", "tool:db:users", 3},
		{"delete", "mcp:github:repos", 2}, // never granted, denied
	}
	for _, t := range traffic {
		for i := 0; i < t.times; i++ {
			_ = guard.Authorize(ctx, toolguard.Call{AgentID: agentID, Tool: t.resource, Action: t.action, Resource: t.resource})
		}
	}

	grants := shrink.StorageGrants{Policies: loadPolicies}
	rows := shrink.AuditRows{Store: store}

	analysis, err := shrink.AnalyzeUsage(ctx, grants, rows, agentID, shrink.AnalyzeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("granted (one entry per action):", len(analysis.Grants))
	fmt.Println("used:")
	for _, u := range analysis.Used {
		fmt.Printf("  %s %s  x%d\n", u.Permission.Resource, u.Permission.Action, u.Count)
	}
	fmt.Println("never used:")
	for _, p := range analysis.Unused {
		fmt.Printf("  %s %s\n", p.Resource, p.Action)
	}

	plan := shrink.SuggestShrink(analysis, shrink.Options{MinObservations: 5})
	fmt.Printf("\nkeep %d, remove %d\n", len(plan.Keep), len(plan.Remove))

	// Proof against the recorded decisions. Review NewlyDenied before applying.
	report, err := shrink.PreviewPolicyChange(ctx, rows, agentID, plan.Keep, shrink.PreviewOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\nrows scanned:   ", report.RowsScanned)
	fmt.Println("replayed allows:", report.ReplayedAllows)
	fmt.Println("still allowed:  ", report.StillAllowed)
	fmt.Println("newly denied:   ", report.NewlyDeniedCount)
	for _, r := range report.NewlyDenied[:min(3, len(report.NewlyDenied))] {
		fmt.Printf("  %s %s\n", r.Action, r.Resource)
	}
	fmt.Println("newly allowed (was denied for lack of a grant):", report.WouldAlsoAllowCount)

	next := policy.Policy{Version: policy.Version, ID: "support-bot", Statements: shrink.Statements(plan.Keep)}
	out, err := next.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nproposed policy:\n%s\n", out)
}

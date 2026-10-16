// Command agent-tool-guard shows the framework-agnostic tool guard: a refund
// tool that runs freely for small amounts and needs a human approval above a
// threshold. The approval id is single use.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/toolguard"
)

type refundArgs struct {
	AgentID string
	Amount  float64
}

func main() {
	doc, err := policy.Parse([]byte(`{"version":"1","statements":[
	  {"effect":"allow","actions":["execute"],"resources":["tool:refund"]}]}`))
	if err != nil {
		log.Fatal(err)
	}
	approvals := toolguard.NewMemoryApprovals()
	g := &toolguard.Guard{
		Evaluator: policy.Evaluator{Risk: []policy.RiskTier{
			{Name: "large-refund", MinAmount: 100, Currency: "USD", Require: policy.RequireApproval},
		}},
		Policies:  func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{doc}, nil },
		Approvals: approvals,
	}

	refund := toolguard.Tool(g,
		func(_ context.Context, a refundArgs) toolguard.Call {
			return toolguard.Call{AgentID: a.AgentID, Tool: "refund", Amount: a.Amount, Currency: "USD"}
		},
		func(_ context.Context, a refundArgs) (string, error) {
			return fmt.Sprintf("refunded %.2f", a.Amount), nil
		})

	ctx := context.Background()
	fmt.Println(refund(ctx, refundArgs{"agent_1", 20}))

	_, err = refund(ctx, refundArgs{"agent_1", 500})
	var need *toolguard.ApprovalRequiredError
	if !errors.As(err, &need) {
		log.Fatalf("expected escalation, got %v", err)
	}
	fmt.Println("needs approval:", need.Tier, need.ApprovalID != "")

	if err := approvals.Approve(need.ApprovalID, "human_1"); err != nil {
		log.Fatal(err)
	}
	retry := toolguard.WithApprovalID(ctx, need.ApprovalID)
	fmt.Println(refund(retry, refundArgs{"agent_1", 500}))
	_, err = refund(retry, refundArgs{"agent_1", 500})
	fmt.Println("second use:", errors.Is(err, toolguard.ErrApprovalRequired))
}

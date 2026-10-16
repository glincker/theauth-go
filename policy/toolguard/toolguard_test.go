package toolguard

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2/policy"
)

func pols(t *testing.T) PoliciesFunc {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":"1","statements":[
	 {"effect":"allow","actions":["execute"],"resources":["tool:*"]},
	 {"effect":"deny","actions":["execute"],"resources":["tool:drop_db"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{p}, nil }
}

func newGuard(t *testing.T) (*Guard, *MemoryApprovals) {
	t.Helper()
	m := NewMemoryApprovals()
	return &Guard{
		Evaluator: policy.Evaluator{Risk: []policy.RiskTier{{Name: "big", MinAmount: 100, Require: policy.RequireApproval}}},
		Policies:  pols(t),
		Approvals: m,
	}, m
}

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name    string
		call    Call
		wantErr error
	}{
		{"allow", Call{AgentID: "a1", Tool: "search"}, nil},
		{"deny", Call{AgentID: "a1", Tool: "drop_db"}, ErrDenied},
		{"escalate", Call{AgentID: "a1", Tool: "pay", Amount: 500}, ErrApprovalRequired},
		{"below tier", Call{AgentID: "a1", Tool: "pay", Amount: 5}, nil},
		{"no agent", Call{Tool: "search"}, ErrGuardFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newGuard(t)
			err := g.Authorize(context.Background(), tc.call)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyLoadFailure(t *testing.T) {
	g, _ := newGuard(t)
	g.Policies = func(context.Context, string) ([]*policy.Policy, error) { return nil, errors.New("db down") }
	if err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "x"}); !errors.Is(err, ErrGuardFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestApprovalSingleUse(t *testing.T) {
	g, m := newGuard(t)
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "pay", Amount: 500}

	err := g.Authorize(ctx, call)
	var are *ApprovalRequiredError
	if !errors.As(err, &are) || are.ApprovalID == "" {
		t.Fatalf("want approval required with id, got %v", err)
	}

	// Pending id does not spend.
	if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), call); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("pending id must not allow, got %v", err)
	}
	if err := m.Approve(are.ApprovalID, "boss"); err != nil {
		t.Fatal(err)
	}
	// Wrong agent and wrong tool do not spend it.
	for _, other := range []Call{{AgentID: "a2", Tool: "pay", Amount: 500}, {AgentID: "a1", Tool: "wire", Amount: 500}} {
		if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), other); !errors.Is(err, ErrApprovalRequired) {
			t.Fatalf("mismatched call must not allow, got %v", err)
		}
	}
	// Matching call spends once.
	if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), call); err != nil {
		t.Fatalf("approved call: %v", err)
	}
	if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), call); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("second use must escalate, got %v", err)
	}
}

func TestApprovalDoesNotOverrideDeny(t *testing.T) {
	g, m := newGuard(t)
	id, err := m.Open(context.Background(), Call{AgentID: "a1", Tool: "drop_db"}, policy.Escalation{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Approve(id, "boss"); err != nil {
		t.Fatal(err)
	}
	err = g.Authorize(WithApprovalID(context.Background(), id), Call{AgentID: "a1", Tool: "drop_db"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestStepUpNotSatisfiedByApproval(t *testing.T) {
	g, m := newGuard(t)
	g.Evaluator.Risk = []policy.RiskTier{{Name: "su", MinAmount: 1, Require: policy.RequireStepUp}}
	call := Call{AgentID: "a1", Tool: "pay", Amount: 10}
	id, _ := m.Open(context.Background(), call, policy.Escalation{})
	_ = m.Approve(id, "boss")
	err := g.Authorize(WithApprovalID(context.Background(), id), call)
	var are *ApprovalRequiredError
	if !errors.As(err, &are) || are.Requirement != policy.RequireStepUp {
		t.Fatalf("got %v", err)
	}
}

func TestNoApprovalsStore(t *testing.T) {
	g, _ := newGuard(t)
	g.Approvals = nil
	err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "pay", Amount: 500})
	var are *ApprovalRequiredError
	if !errors.As(err, &are) || are.ApprovalID != "" {
		t.Fatalf("got %v", err)
	}
}

func TestToolWrapperRunsOnlyOnAllow(t *testing.T) {
	g, _ := newGuard(t)
	type args struct {
		Agent, Tool string
		Amount      float64
	}
	ran := 0
	fn := Tool(g,
		func(_ context.Context, a args) Call { return Call{AgentID: a.Agent, Tool: a.Tool, Amount: a.Amount} },
		func(_ context.Context, a args) (string, error) { ran++; return "ok", nil })
	tests := []struct {
		name    string
		in      args
		want    string
		wantErr error
		wantRan int
	}{
		{"allow", args{"a1", "search", 0}, "ok", nil, 1},
		{"deny", args{"a1", "drop_db", 0}, "", ErrDenied, 1},
		{"escalate", args{"a1", "pay", 999}, "", ErrApprovalRequired, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fn(context.Background(), tc.in)
			if !errors.Is(err, tc.wantErr) || got != tc.want || ran != tc.wantRan {
				t.Fatalf("got (%q, %v) ran=%d", got, err, ran)
			}
		})
	}
}

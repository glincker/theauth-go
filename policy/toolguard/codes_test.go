package toolguard

import (
	"context"
	"errors"
	"fmt"
	"testing"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
)

func TestDeniedErrorCode(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "drop_db"})
	wrapped := fmt.Errorf("handler: %w", err)
	var denied *DeniedError
	if !errors.As(wrapped, &denied) {
		t.Fatalf("errors.As failed for %v", wrapped)
	}
	if denied.Code != policy.CodeNoPermission {
		t.Fatalf("Code = %q", denied.Code)
	}
	if got := CodeOf(wrapped); got != policy.CodeNoPermission {
		t.Fatalf("CodeOf = %q", got)
	}
	if CodeOf(nil) != "" || CodeOf(errors.New("plain")) != "" {
		t.Fatal("CodeOf must be empty for nil and uncoded errors")
	}
}

func TestToolguardErrorCodes(t *testing.T) {
	t.Parallel()
	escalateStmt, err := policy.Parse([]byte(`{"version":"1","statements":[{"effect":"escalate","actions":["execute"],"resources":["tool:wire"]},{"effect":"allow","actions":["execute"],"resources":["tool:*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	taintGuard := func(t *testing.T) *Guard {
		g, _ := newGuard(t)
		g.Evaluator.Taint = []policy.TaintRule{{Resource: "tool:*", Forbid: []string{"untrusted"}, Effect: policy.Deny}}
		return g
	}
	tests := []struct {
		name  string
		setup func(t *testing.T) *Guard
		call  Call
		want  policy.DecisionCode
	}{
		{"deny", func(t *testing.T) *Guard { g, _ := newGuard(t); return g }, Call{AgentID: "a1", Tool: "drop_db"}, policy.CodeNoPermission},
		{"risk escalation", func(t *testing.T) *Guard { g, _ := newGuard(t); return g }, Call{AgentID: "a1", Tool: "pay", Amount: 500}, policy.CodeRiskEscalation},
		{"statement escalation", func(t *testing.T) *Guard {
			g, _ := newGuard(t)
			g.Policies = func(context.Context, string) ([]*policy.Policy, error) { return []*policy.Policy{escalateStmt}, nil }
			return g
		}, Call{AgentID: "a1", Tool: "wire"}, policy.CodeApprovalRequired},
		{"taint deny", taintGuard, Call{AgentID: "a1", Tool: "search", Provenance: map[string][]string{policy.CallLabelsKey: {"untrusted"}}}, policy.CodeTaintViolation},
		{"rate limited", func(t *testing.T) *Guard {
			g, _ := newGuard(t)
			g.Limit = func(context.Context, string) error { return &theauth.AgentRateLimitedError{} }
			return g
		}, Call{AgentID: "a1", Tool: "search"}, policy.CodeRateLimited},
		{"agent not found", func(t *testing.T) *Guard {
			g, _ := newGuard(t)
			g.Limit = func(context.Context, string) error { return theauth.ErrAgentNotFound }
			return g
		}, Call{AgentID: "a1", Tool: "search"}, policy.CodeAgentNotFound},
		{"limit failure", func(t *testing.T) *Guard {
			g, _ := newGuard(t)
			g.Limit = func(context.Context, string) error { return errors.New("kv down") }
			return g
		}, Call{AgentID: "a1", Tool: "search"}, policy.CodePolicyIndeterminate},
		{"policy load failure", func(t *testing.T) *Guard {
			g, _ := newGuard(t)
			g.Policies = func(context.Context, string) ([]*policy.Policy, error) { return nil, errors.New("db down") }
			return g
		}, Call{AgentID: "a1", Tool: "search"}, policy.CodePolicyIndeterminate},
		{"no agent id", func(t *testing.T) *Guard { g, _ := newGuard(t); return g }, Call{Tool: "search"}, policy.CodePolicyIndeterminate},
		{"no policy source", func(t *testing.T) *Guard { return &Guard{} }, Call{AgentID: "a1", Tool: "search"}, policy.CodePolicyIndeterminate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.setup(t).Authorize(context.Background(), tc.call)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := CodeOf(err); got != tc.want {
				t.Fatalf("CodeOf = %q, want %q (err %v)", got, tc.want, err)
			}
		})
	}
}

func TestGuardFailedKeepsSentinelsAndText(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	cause := errors.New("kv down")
	g.Limit = func(context.Context, string) error { return cause }
	err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "x"})
	if !errors.Is(err, ErrGuardFailed) || !errors.Is(err, cause) {
		t.Fatalf("sentinels lost: %v", err)
	}
	if want := "toolguard: check failed: limit for agent a1: kv down"; err.Error() != want {
		t.Fatalf("text = %q, want %q", err.Error(), want)
	}
}

func TestApprovalCodes(t *testing.T) {
	t.Parallel()
	g, m := newGuard(t)
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "pay", Amount: 500}
	err := g.Authorize(ctx, call)
	var are *ApprovalRequiredError
	if !errors.As(err, &are) || are.Code != policy.CodeRiskEscalation {
		t.Fatalf("first: %v", err)
	}
	id := are.ApprovalID
	err = g.Authorize(WithApprovalID(ctx, id), call)
	if !errors.As(err, &are) || are.Code != policy.CodeApprovalPending || are.ApprovalID != id {
		t.Fatalf("pending id: %v", err)
	}
	if err := m.Approve(id, "boss"); err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(WithApprovalID(ctx, id), call); err != nil {
		t.Fatalf("approved: %v", err)
	}
}

func TestAuditCarriesDecisionCode(t *testing.T) {
	t.Parallel()
	prov := map[string][]string{policy.CallLabelsKey: {"user_input"}}
	run := func(t *testing.T, g *Guard, ctx context.Context, c Call) map[string]any {
		var got map[string]any
		g.Audit = func(_ context.Context, _ string, _ theauth.TargetRef, md map[string]any) { got = md }
		_ = g.Authorize(ctx, c)
		if got == nil {
			t.Fatal("no audit record")
		}
		return got
	}
	t.Run("allowed", func(t *testing.T) {
		g, _ := newGuard(t)
		md := run(t, g, context.Background(), Call{AgentID: "a1", Tool: "search", Provenance: prov})
		if md["decision_code"] != "allowed" || md["outcome"] != "allowed" || md["reason"] == nil {
			t.Fatalf("md = %v", md)
		}
	})
	t.Run("denied", func(t *testing.T) {
		g, _ := newGuard(t)
		md := run(t, g, context.Background(), Call{AgentID: "a1", Tool: "drop_db", Provenance: prov})
		if md["decision_code"] != "no_permission" {
			t.Fatalf("md = %v", md)
		}
	})
	t.Run("approval consumed", func(t *testing.T) {
		g, m := newGuard(t)
		call := Call{AgentID: "a1", Tool: "pay", Amount: 500, Provenance: prov}
		id, _ := m.Open(context.Background(), call, policy.Escalation{})
		_ = m.Approve(id, "boss")
		md := run(t, g, WithApprovalID(context.Background(), id), call)
		if md["decision_code"] != "approval_consumed" || md["outcome"] != "approved" {
			t.Fatalf("md = %v", md)
		}
	})
}

package toolguard

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/hook"
)

func TestHookCodesMatchPolicyCodes(t *testing.T) {
	pairs := map[hook.Code]policy.DecisionCode{
		hook.CodeHookDenied:       policy.CodeHookDenied,
		hook.CodeHookTimeout:      policy.CodeHookTimeout,
		hook.CodeHookError:        policy.CodeHookError,
		hook.CodeApprovalRequired: policy.CodeApprovalRequired,
	}
	for h, p := range pairs {
		if string(h) != string(p) || !p.Valid() {
			t.Fatalf("hook code %q does not match policy code %q", h, p)
		}
	}
}

type auditRec struct {
	action string
	meta   map[string]any
}

// hookGuard builds a guard whose hook returns v (or err), counting calls and
// recording audit events.
func hookGuard(t *testing.T, h hook.Hook) (*Guard, *MemoryApprovals, *atomic.Int32, *[]auditRec) {
	t.Helper()
	g, m := newGuard(t)
	var calls atomic.Int32
	var audits []auditRec
	g.BeforeAuthorize = &hook.Runner{Timeout: 50 * time.Millisecond, Hook: hook.Func(func(ctx context.Context, in hook.Input) (hook.Verdict, error) {
		calls.Add(1)
		return h.BeforeAuthorize(ctx, in)
	})}
	g.Audit = func(_ context.Context, action string, _ theauth.TargetRef, meta map[string]any) {
		audits = append(audits, auditRec{action, meta})
	}
	return g, m, &calls, &audits
}

func fixed(v hook.Verdict) hook.Hook {
	return hook.Func(func(context.Context, hook.Input) (hook.Verdict, error) { return v, nil })
}

func TestGuardHookOutcomes(t *testing.T) {
	slow := hook.Func(func(ctx context.Context, _ hook.Input) (hook.Verdict, error) {
		<-ctx.Done()
		return hook.Verdict{}, ctx.Err()
	})
	panics := hook.Func(func(context.Context, hook.Input) (hook.Verdict, error) { panic("boom") })
	failing := hook.Func(func(context.Context, hook.Input) (hook.Verdict, error) { return hook.Verdict{}, errors.New("down") })
	tests := []struct {
		name      string
		hook      hook.Hook
		call      Call
		wantErr   error
		wantCode  policy.DecisionCode
		wantCalls int32
		wantAudit bool
	}{
		{"allow keeps allow", fixed(hook.Verdict{Decision: hook.Allow}), Call{AgentID: "a1", Tool: "search"}, nil, "", 1, false},
		{"deny refuses", fixed(hook.Verdict{Decision: hook.Deny, Reason: "vendor says no"}), Call{AgentID: "a1", Tool: "search"}, ErrDenied, policy.CodeHookDenied, 1, true},
		{"timeout fails closed", slow, Call{AgentID: "a1", Tool: "search"}, ErrDenied, policy.CodeHookTimeout, 1, true},
		{"panic fails closed", panics, Call{AgentID: "a1", Tool: "search"}, ErrDenied, policy.CodeHookError, 1, true},
		{"error fails closed", failing, Call{AgentID: "a1", Tool: "search"}, ErrDenied, policy.CodeHookError, 1, true},
		{"malformed fails closed", fixed(hook.Verdict{}), Call{AgentID: "a1", Tool: "search"}, ErrDenied, policy.CodeHookError, 1, true},
		{"escalate turns allow into approval", fixed(hook.Verdict{Decision: hook.Escalate, Reason: "human please"}), Call{AgentID: "a1", Tool: "search"}, ErrApprovalRequired, policy.CodeApprovalRequired, 1, true},
		{"policy deny skips the hook", fixed(hook.Verdict{Decision: hook.Allow}), Call{AgentID: "a1", Tool: "drop_db"}, ErrDenied, policy.CodeNoPermission, 0, false},
		{"hook allow does not lift a policy escalation", fixed(hook.Verdict{Decision: hook.Allow}), Call{AgentID: "a1", Tool: "pay", Amount: 500}, ErrApprovalRequired, policy.CodeRiskEscalation, 1, false},
		{"hook deny beats a policy escalation", fixed(hook.Verdict{Decision: hook.Deny, Reason: "no"}), Call{AgentID: "a1", Tool: "pay", Amount: 500}, ErrDenied, policy.CodeHookDenied, 1, true},
		{"map arguments pass through unchanged", fixed(hook.Verdict{Decision: hook.Allow}), Call{AgentID: "a1", Tool: "search", Args: map[string]any{"c": make(chan int)}}, nil, "", 1, false},
		{"unencodable typed arguments fail closed", fixed(hook.Verdict{Decision: hook.Allow}), Call{AgentID: "a1", Tool: "search", Args: struct{ C chan int }{}}, ErrDenied, policy.CodeHookError, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _, calls, audits := hookGuard(t, tc.hook)
			err := g.Authorize(context.Background(), tc.call)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Fatalf("code %q, want %q", got, tc.wantCode)
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("hook calls %d, want %d", calls.Load(), tc.wantCalls)
			}
			if tc.wantAudit {
				if len(*audits) != 1 {
					t.Fatalf("want one audit record, got %d", len(*audits))
				}
				a := (*audits)[0]
				outcome := "denied"
				if errors.Is(err, ErrApprovalRequired) {
					outcome = "approval_required"
				}
				if a.action != "agent.authorize" || a.meta["decision_code"] != string(tc.wantCode) || a.meta["outcome"] != outcome || a.meta["hook"] == nil {
					t.Fatalf("audit record %+v", a)
				}
			} else if len(*audits) != 0 {
				t.Fatalf("unexpected audit records %+v", *audits)
			}
		})
	}
}

func TestGuardHookEscalationUsesApprovals(t *testing.T) {
	g, m, calls, _ := hookGuard(t, fixed(hook.Verdict{Decision: hook.Escalate, Reason: "human please"}))
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "search"}
	var are *ApprovalRequiredError
	if err := g.Authorize(ctx, call); !errors.As(err, &are) || are.ApprovalID == "" || are.Reason != "human please" {
		t.Fatalf("want approval required with id, got %v", err)
	}
	if err := m.Approve(are.ApprovalID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), call); err != nil {
		t.Fatalf("approved call refused: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("hook calls %d, want 2", calls.Load())
	}
}

func TestGuardHookInput(t *testing.T) {
	var got hook.Input
	g, _, _, _ := hookGuard(t, hook.Func(func(_ context.Context, in hook.Input) (hook.Verdict, error) {
		got = in
		return hook.Verdict{Decision: hook.Allow}, nil
	}))
	g.HookSubject = func(context.Context, string) (hook.AgentInfo, hook.Delegation, error) {
		return hook.AgentInfo{ID: "a1", OwnerID: "u1", Name: "bot"}, hook.Delegation{RootOwnerID: "u1", Path: []string{"a1"}}, nil
	}
	type args struct {
		Query string `json:"query"`
	}
	if err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "search", Args: args{Query: "bugs"}}); err != nil {
		t.Fatal(err)
	}
	if got.Action != "execute" || got.Resource != "tool:search" || got.Agent.OwnerID != "u1" ||
		got.Arguments["query"] != "bugs" || got.Source != hook.SourceAuthorize {
		t.Fatalf("hook input %+v", got)
	}
}

func TestGuardHookSubjectFailureFailsClosed(t *testing.T) {
	g, _, calls, _ := hookGuard(t, fixed(hook.Verdict{Decision: hook.Allow}))
	g.HookSubject = func(context.Context, string) (hook.AgentInfo, hook.Delegation, error) {
		return hook.AgentInfo{}, hook.Delegation{}, errors.New("db down")
	}
	err := g.Authorize(context.Background(), Call{AgentID: "a1", Tool: "search"})
	if !errors.Is(err, ErrGuardFailed) || CodeOf(err) != policy.CodePolicyIndeterminate {
		t.Fatalf("got %v (%s)", err, CodeOf(err))
	}
	if calls.Load() != 0 {
		t.Fatal("hook must not run without its input")
	}
}

func TestGuardHookToolDoesNotRun(t *testing.T) {
	g, _, _, _ := hookGuard(t, fixed(hook.Verdict{Decision: hook.Deny, Reason: "no"}))
	ran := false
	tool := Tool(g, func(_ context.Context, q string) Call { return Call{AgentID: "a1", Tool: "search"} },
		func(context.Context, string) (string, error) { ran = true; return "ok", nil })
	if _, err := tool(context.Background(), "q"); !errors.Is(err, ErrDenied) || ran {
		t.Fatalf("err %v, ran %v", err, ran)
	}
}

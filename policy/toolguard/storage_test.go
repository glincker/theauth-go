package toolguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func TestStorageApprovalsFlow(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		approve   bool
		advance   time.Duration
		retry     Call
		wantSpend bool
	}{
		{"approved same call", true, 0, Call{AgentID: "a1", Tool: "pay", Amount: 500}, true},
		{"never approved", false, 0, Call{AgentID: "a1", Tool: "pay", Amount: 500}, false},
		{"other agent", true, 0, Call{AgentID: "a2", Tool: "pay", Amount: 500}, false},
		{"other tool", true, 0, Call{AgentID: "a1", Tool: "refund", Amount: 500}, false},
		{"expired", true, 2 * time.Hour, Call{AgentID: "a1", Tool: "pay", Amount: 500}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := base
			ap := NewStorageApprovals(memory.New(), WithApprovalClock(func() time.Time { return now }))
			g := &Guard{
				Evaluator: policy.Evaluator{Risk: []policy.RiskTier{{Name: "big", MinAmount: 100, Require: policy.RequireApproval}}},
				Policies:  pols(t),
				Approvals: ap,
			}
			ctx := context.Background()
			err := g.Authorize(ctx, Call{AgentID: "a1", Tool: "pay", Amount: 500})
			var are *ApprovalRequiredError
			if !errors.As(err, &are) || are.ApprovalID == "" {
				t.Fatalf("want approval id, got %v", err)
			}
			if tc.approve {
				if err := ap.Approve(ctx, are.ApprovalID, "alice"); err != nil {
					t.Fatal(err)
				}
			}
			now = now.Add(tc.advance)
			err = g.Authorize(WithApprovalID(ctx, are.ApprovalID), tc.retry)
			if tc.wantSpend {
				if err != nil {
					t.Fatalf("retry denied: %v", err)
				}
				if err := g.Authorize(WithApprovalID(ctx, are.ApprovalID), tc.retry); !errors.Is(err, ErrApprovalRequired) {
					t.Fatalf("second spend = %v, want approval required", err)
				}
				return
			}
			if !errors.Is(err, ErrApprovalRequired) {
				t.Fatalf("got %v, want approval required", err)
			}
		})
	}
}

func TestStorageApprovalsApproveErrors(t *testing.T) {
	ap := NewStorageApprovals(memory.New())
	ctx := context.Background()
	if err := ap.Approve(ctx, "missing", "alice"); err == nil {
		t.Fatal("approve of unknown id succeeded")
	}
	id, err := ap.Open(ctx, Call{AgentID: "a1", Tool: "pay"}, policy.Escalation{Requirement: policy.RequireApproval})
	if err != nil {
		t.Fatal(err)
	}
	if err := ap.Approve(ctx, id, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := ap.Approve(ctx, id, "bob"); err == nil {
		t.Fatal("double approve succeeded")
	}
}

func TestStorageApprovalsConcurrentConsume(t *testing.T) {
	ap := NewStorageApprovals(memory.New(), WithApprovalTTL(0))
	ctx := context.Background()
	call := Call{AgentID: "a1", Tool: "pay"}
	id, err := ap.Open(ctx, call, policy.Escalation{Requirement: policy.RequireApproval})
	if err != nil {
		t.Fatal(err)
	}
	if err := ap.Approve(ctx, id, "alice"); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := ap.Consume(ctx, id, call); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners, want 1", wins.Load())
	}
}

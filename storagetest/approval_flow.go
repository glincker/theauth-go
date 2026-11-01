package storagetest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/toolguard"
)

// RunApprovalFlow runs the approval flow against a store through toolguard.StorageApprovals: the
// specific approval_* denial codes, arguments binding, single use under a concurrent double
// spend, and a decide race. It is the end to end counterpart of RunToolApprovals and
// RunToolApprovalAdmin, and every built in store must pass it.
func RunApprovalFlow(t *testing.T, store theauth.ToolApprovalAdminStorage) {
	t.Helper()
	t.Run("ApprovalFlow", func(t *testing.T) { testApprovalFlow(t, store) })
}

func testApprovalFlow(t *testing.T, store theauth.ToolApprovalAdminStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	ap := toolguard.NewStorageApprovals(store, toolguard.WithApprovalClock(clock), toolguard.WithApprovalTTL(time.Minute))
	esc := policy.Escalation{Requirement: policy.RequireApproval}
	call := toolguard.Call{AgentID: "agent-flow", Tool: "pay", Args: map[string]any{"to": "bob", "amount": 5}}
	open := func(t *testing.T) string {
		t.Helper()
		id, err := ap.Open(ctx, call, esc)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		return id
	}
	spend := func(t *testing.T, id string, c toolguard.Call) policy.DecisionCode {
		t.Helper()
		code, err := ap.Spend(ctx, id, c)
		if err != nil {
			t.Fatalf("spend: %v", err)
		}
		return code
	}
	approve := func(t *testing.T, id string) {
		t.Helper()
		if err := ap.Approve(ctx, id, "alice"); err != nil {
			t.Fatalf("approve: %v", err)
		}
	}

	t.Run("denial codes", func(t *testing.T) {
		if got := spend(t, "missing", call); got != policy.CodeApprovalNotFound {
			t.Errorf("unknown id: %q", got)
		}
		id := open(t)
		if got := spend(t, id, call); got != policy.CodeApprovalPending {
			t.Errorf("pending: %q", got)
		}
		denied := open(t)
		if err := ap.Deny(ctx, denied, "alice"); err != nil {
			t.Fatal(err)
		}
		if got := spend(t, denied, call); got != policy.CodeApprovalDenied {
			t.Errorf("denied: %q", got)
		}
		approve(t, id)
		other := call
		other.AgentID = "agent-other"
		if got := spend(t, id, other); got != policy.CodeApprovalMismatch {
			t.Errorf("other agent: %q", got)
		}
		other = call
		other.Tool = "refund"
		if got := spend(t, id, other); got != policy.CodeApprovalMismatch {
			t.Errorf("other tool: %q", got)
		}
		if got := spend(t, id, call); got != policy.CodeApprovalConsumed {
			t.Errorf("spend after mismatches: %q", got)
		}
		if got := spend(t, id, call); got != policy.CodeApprovalAlreadyUsed {
			t.Errorf("replay: %q", got)
		}
	})
	t.Run("arguments bound", func(t *testing.T) {
		id := open(t)
		approve(t, id)
		other := call
		other.Args = map[string]any{"to": "eve", "amount": 5}
		if got := spend(t, id, other); got != policy.CodeApprovalArgumentsMismatch {
			t.Fatalf("other arguments: %q", got)
		}
		reordered := call
		reordered.Args = map[string]any{"amount": 5, "to": "bob", "theauthTrace": "ignored"}
		if got := spend(t, id, reordered); got != policy.CodeApprovalConsumed {
			t.Fatalf("same arguments in another order: %q", got)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		pastClock := now
		past := toolguard.NewStorageApprovals(store, toolguard.WithApprovalClock(func() time.Time { return pastClock }), toolguard.WithApprovalTTL(time.Minute))
		id, err := past.Open(ctx, call, esc)
		if err != nil {
			t.Fatal(err)
		}
		pastClock = now.Add(2 * time.Minute)
		if got, _ := past.Spend(ctx, id, call); got != policy.CodeApprovalExpired {
			t.Fatalf("unanswered: %q", got)
		}
		if _, err := past.Decide(ctx, id, toolguard.DecideInput{Decision: toolguard.DecisionApprove, DecidedBy: "alice"}); err == nil {
			t.Fatal("decided an expired request")
		}
		pastClock = now
		id2, _ := past.Open(ctx, call, esc)
		if err := past.Approve(ctx, id2, "alice"); err != nil {
			t.Fatal(err)
		}
		pastClock = now.Add(2 * time.Minute)
		if got, _ := past.Spend(ctx, id2, call); got != policy.CodeApprovalExpired {
			t.Fatalf("approved but overdue: %q", got)
		}
	})
	t.Run("concurrent double spend", func(t *testing.T) {
		id := open(t)
		approve(t, id)
		const n = 24
		var wins, used, errs atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				code, err := ap.Spend(ctx, id, call)
				switch {
				case err != nil:
					errs.Add(1)
				case code == policy.CodeApprovalConsumed:
					wins.Add(1)
				case code == policy.CodeApprovalAlreadyUsed:
					used.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || used.Load() != n-1 || errs.Load() != 0 {
			t.Fatalf("%d won, %d already used, %d errors out of %d", wins.Load(), used.Load(), errs.Load(), n)
		}
	})
	t.Run("concurrent decide", func(t *testing.T) {
		id := open(t)
		var ok, lost atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				d := toolguard.DecisionApprove
				if i%2 == 1 {
					d = toolguard.DecisionDeny
				}
				if _, err := ap.Decide(ctx, id, toolguard.DecideInput{Decision: d, DecidedBy: "alice"}); err == nil {
					ok.Add(1)
				} else {
					lost.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if ok.Load() != 1 || lost.Load() != 15 {
			t.Fatalf("%d decisions succeeded, %d rejected, want 1 and 15", ok.Load(), lost.Load())
		}
	})
}

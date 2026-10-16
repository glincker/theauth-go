package storagetest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// RunToolApprovals runs the single use tool approval contract tests.
func RunToolApprovals(t *testing.T, store theauth.ToolApprovalStorage) {
	t.Helper()
	t.Run("ToolApprovals", func(t *testing.T) { testToolApprovals(t, store) })
}

func testToolApprovals(t *testing.T, store theauth.ToolApprovalStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	open := func(t *testing.T, expires time.Time) string {
		t.Helper()
		id := newID().String()
		a := theauth.ToolApproval{
			ID: id, AgentID: "agent-1", Action: "execute", Resource: "tool:pay",
			Requirement: "approval", Tier: "big", Reason: "over limit", CreatedAt: now, ExpiresAt: expires,
		}
		if err := store.OpenToolApproval(ctx, a); err != nil {
			t.Fatalf("open: %v", err)
		}
		return id
	}
	consume := func(id string, at time.Time) bool {
		ok, err := store.ConsumeToolApproval(ctx, id, "agent-1", "execute", "tool:pay", at)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		return ok
	}

	t.Run("pending is not spendable", func(t *testing.T) {
		if consume(open(t, time.Time{}), now) {
			t.Fatal("pending approval was consumed")
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		if consume("nope", now) {
			t.Fatal("unknown id was consumed")
		}
		if ok, err := store.ApproveToolApproval(ctx, "nope", "alice", now); err != nil || ok {
			t.Fatalf("approve unknown = %v, %v", ok, err)
		}
	})
	t.Run("approve then consume once", func(t *testing.T) {
		id := open(t, now.Add(time.Hour))
		if ok, err := store.ApproveToolApproval(ctx, id, "alice", now); err != nil || !ok {
			t.Fatalf("approve = %v, %v", ok, err)
		}
		if ok, _ := store.ApproveToolApproval(ctx, id, "bob", now); ok {
			t.Fatal("second approve succeeded")
		}
		if !consume(id, now) {
			t.Fatal("first consume failed")
		}
		if consume(id, now) {
			t.Fatal("second consume succeeded")
		}
		if ok, _ := store.ApproveToolApproval(ctx, id, "alice", now); ok {
			t.Fatal("approve after consume succeeded")
		}
	})
	t.Run("binding mismatch does not spend", func(t *testing.T) {
		id := open(t, time.Time{})
		if _, err := store.ApproveToolApproval(ctx, id, "alice", now); err != nil {
			t.Fatal(err)
		}
		cases := []struct{ agent, action, resource string }{
			{"agent-2", "execute", "tool:pay"},
			{"agent-1", "read", "tool:pay"},
			{"agent-1", "execute", "tool:refund"},
		}
		for _, c := range cases {
			ok, err := store.ConsumeToolApproval(ctx, id, c.agent, c.action, c.resource, now)
			if err != nil || ok {
				t.Fatalf("mismatch %+v = %v, %v", c, ok, err)
			}
		}
		if !consume(id, now) {
			t.Fatal("matching consume failed after mismatches")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		id := open(t, now.Add(time.Minute))
		if _, err := store.ApproveToolApproval(ctx, id, "alice", now); err != nil {
			t.Fatal(err)
		}
		if consume(id, now.Add(time.Minute)) {
			t.Fatal("expired approval was consumed")
		}
		late := open(t, now.Add(time.Minute))
		if ok, _ := store.ApproveToolApproval(ctx, late, "alice", now.Add(2*time.Minute)); ok {
			t.Fatal("expired request was approved")
		}
	})
	t.Run("duplicate id", func(t *testing.T) {
		id := open(t, time.Time{})
		err := store.OpenToolApproval(ctx, theauth.ToolApproval{ID: id, AgentID: "a", Action: "x", Resource: "y", CreatedAt: now})
		if err == nil {
			t.Fatal("duplicate id accepted")
		}
	})
	t.Run("concurrent consume exactly once", func(t *testing.T) {
		id := open(t, time.Time{})
		if _, err := store.ApproveToolApproval(ctx, id, "alice", now); err != nil {
			t.Fatal(err)
		}
		const n = 24
		var wins, errs atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ok, err := store.ConsumeToolApproval(ctx, id, "agent-1", "execute", "tool:pay", now)
				if err != nil {
					errs.Add(1)
				}
				if ok {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d consumers won, want exactly 1 (%d errors)", wins.Load(), errs.Load())
		}
	})
}

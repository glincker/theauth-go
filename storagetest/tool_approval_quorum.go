package storagetest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// QuorumStore is what RunToolApprovalQuorum needs from a store.
type QuorumStore interface {
	theauth.ToolApprovalAdminStorage
	theauth.ToolApprovalQuorumStorage
}

// RunToolApprovalQuorum runs the quorum (two person) approval contract tests: distinct approvers,
// the requester never counts, expiry covers the whole quorum, the single approver path cannot
// skip a quorum, and concurrent votes count once and complete exactly once.
func RunToolApprovalQuorum(t *testing.T, store QuorumStore) {
	t.Helper()
	t.Run("ToolApprovalQuorum", func(t *testing.T) { testToolApprovalQuorum(t, store) })
}

func testToolApprovalQuorum(t *testing.T, store QuorumStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	open := func(t *testing.T, required int, expires time.Time) string {
		t.Helper()
		id := newID().String()
		a := theauth.ToolApproval{
			ID: id, AgentID: "agent-1", Action: "move", Resource: "robot:arm", OpenedBy: "opener",
			ArgumentsHash: "abc", CreatedAt: now, ExpiresAt: expires, RequiredApprovals: required,
		}
		if err := store.OpenToolApproval(ctx, a); err != nil {
			t.Fatalf("open: %v", err)
		}
		return id
	}
	vote := func(t *testing.T, id, who string, at time.Time) theauth.ToolApprovalVote {
		t.Helper()
		v, err := store.VoteToolApproval(ctx, id, who, at)
		if err != nil {
			t.Fatalf("vote %s: %v", who, err)
		}
		return v
	}
	consume := func(id string, at time.Time) bool {
		ok, err := store.ConsumeToolApproval(ctx, id, "agent-1", "move", "robot:arm", at)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		return ok
	}

	t.Run("needs the whole quorum before it can be spent", func(t *testing.T) {
		id := open(t, 2, now.Add(time.Hour))
		if v := vote(t, id, "alice", now); v.Outcome != theauth.VoteCounted || len(v.Approvers) != 1 {
			t.Fatalf("first vote = %+v", v)
		}
		if consume(id, now) {
			t.Fatal("spent before the quorum was complete")
		}
		got, _, _ := store.GetToolApproval(ctx, id)
		if !got.ApprovedAt.IsZero() || got.RequiredApprovals != 2 || len(got.Approvers) != 1 || got.Approvers[0] != "alice" {
			t.Fatalf("after one vote = %+v", got)
		}
		if v := vote(t, id, "bob", now.Add(time.Second)); v.Outcome != theauth.VoteCompleted || len(v.Approvers) != 2 {
			t.Fatalf("second vote = %+v", v)
		}
		got, _, _ = store.GetToolApproval(ctx, id)
		if got.ApprovedAt.IsZero() || got.Approver != "bob" || len(got.Approvers) != 2 {
			t.Fatalf("after quorum = %+v", got)
		}
		if !consume(id, now) {
			t.Fatal("complete quorum was not spendable")
		}
		if consume(id, now) {
			t.Fatal("spent twice")
		}
	})
	t.Run("approvers are distinct and never the requester", func(t *testing.T) {
		id := open(t, 3, now.Add(time.Hour))
		if v := vote(t, id, "opener", now); v.Outcome != theauth.VoteRequester {
			t.Fatalf("requester vote = %+v", v)
		}
		vote(t, id, "alice", now)
		if v := vote(t, id, "alice", now); v.Outcome != theauth.VoteDuplicate || len(v.Approvers) != 1 {
			t.Fatalf("duplicate vote = %+v", v)
		}
		got, _, _ := store.GetToolApproval(ctx, id)
		if len(got.Approvers) != 1 {
			t.Fatalf("approvers = %v", got.Approvers)
		}
	})
	t.Run("the single approver path cannot skip a quorum", func(t *testing.T) {
		id := open(t, 2, now.Add(time.Hour))
		if ok, err := store.ApproveToolApproval(ctx, id, "alice", now); err != nil || ok {
			t.Fatalf("approve on a quorum request = %v, %v", ok, err)
		}
		single := open(t, 1, now.Add(time.Hour))
		if v := vote(t, single, "alice", now); v.Outcome != theauth.VoteNotPending {
			t.Fatalf("vote on a single approver request = %+v", v)
		}
		if ok, err := store.ApproveToolApproval(ctx, single, "alice", now); err != nil || !ok {
			t.Fatalf("approve single = %v, %v", ok, err)
		}
		if v := vote(t, "nope", "alice", now); v.Outcome != theauth.VoteNotPending {
			t.Fatalf("vote on an unknown id = %+v", v)
		}
	})
	t.Run("a denial or an expiry stops the quorum", func(t *testing.T) {
		denied := open(t, 2, now.Add(time.Hour))
		vote(t, denied, "alice", now)
		if ok, err := store.DenyToolApproval(ctx, denied, "bob", now); err != nil || !ok {
			t.Fatalf("deny = %v, %v", ok, err)
		}
		if v := vote(t, denied, "carol", now); v.Outcome != theauth.VoteNotPending {
			t.Fatalf("vote after deny = %+v", v)
		}

		late := open(t, 2, now.Add(time.Minute))
		vote(t, late, "alice", now)
		if v := vote(t, late, "bob", now.Add(time.Hour)); v.Outcome != theauth.VoteNotPending {
			t.Fatalf("vote after expiry = %+v", v)
		}
		got, _, _ := store.GetToolApproval(ctx, late)
		if !got.ApprovedAt.IsZero() {
			t.Fatal("an expired quorum was approved")
		}
	})
	t.Run("one approver racing with themselves counts once", func(t *testing.T) {
		id := open(t, 2, now.Add(time.Hour))
		var counted atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, err := store.VoteToolApproval(ctx, id, "alice", now)
				if err != nil {
					t.Errorf("vote: %v", err)
					return
				}
				if v.Outcome == theauth.VoteCounted {
					counted.Add(1)
				}
			}()
		}
		wg.Wait()
		if counted.Load() != 1 {
			t.Fatalf("counted %d times, want 1", counted.Load())
		}
		got, _, _ := store.GetToolApproval(ctx, id)
		if len(got.Approvers) != 1 || !got.ApprovedAt.IsZero() {
			t.Fatalf("after the race = %+v", got)
		}
	})
	t.Run("many approvers racing complete it once", func(t *testing.T) {
		id := open(t, 2, now.Add(time.Hour))
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.VoteToolApproval(ctx, id, fmt.Sprintf("approver-%d", i), now); err != nil {
					t.Errorf("vote: %v", err)
				}
			}()
		}
		wg.Wait()
		got, _, _ := store.GetToolApproval(ctx, id)
		if got.ApprovedAt.IsZero() || len(got.Approvers) < 2 {
			t.Fatalf("after the race = %+v", got)
		}
		found := false
		for _, who := range got.Approvers {
			found = found || who == got.Approver
		}
		if !found {
			t.Fatalf("approver %q is not among %v", got.Approver, got.Approvers)
		}
		var spent atomic.Int32
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if consume(id, now) {
					spent.Add(1)
				}
			}()
		}
		wg.Wait()
		if spent.Load() != 1 {
			t.Fatalf("spent %d times, want 1", spent.Load())
		}
	})
}

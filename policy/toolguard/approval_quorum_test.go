package toolguard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func quorumApprovals(now *time.Time, rec *recorder, n int) *StorageApprovals {
	return NewStorageApprovals(memory.New(),
		WithApprovalClock(func() time.Time { return *now }),
		WithApprovalTTL(time.Minute),
		WithApprovalAudit(rec.audit),
		WithApprovalEvents(rec.event),
		WithApprovalQuorum(func(Call, policy.Escalation) int { return n }))
}

func TestStorageApprovalsQuorum(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	call := Call{AgentID: "robot-1", Tool: "arm", OpenedBy: "fleet-owner", Args: map[string]any{"speed": 5}}
	esc := policy.Escalation{Requirement: policy.RequireApproval}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	decide := func(ap *StorageApprovals, id, who string) error {
		_, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: who})
		return err
	}

	t.Run("two approvers, audited each, spent once", func(t *testing.T) {
		rec := &recorder{}
		ap := quorumApprovals(&now, rec, 2)
		id, err := ap.Open(ctx, call, esc)
		if err != nil {
			t.Fatal(err)
		}
		first, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: "alice"})
		if err != nil || !first.ApprovedAt.IsZero() || len(first.Approvers) != 1 {
			t.Fatalf("first = %+v, %v", first, err)
		}
		if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalPending {
			t.Fatalf("spend before the quorum = %q", code)
		}
		second, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: "bob"})
		if err != nil || second.ApprovedAt.IsZero() || second.Approver != "bob" || len(second.Approvers) != 2 {
			t.Fatalf("second = %+v, %v", second, err)
		}
		if code, err := ap.Spend(ctx, id, call); err != nil || code != policy.CodeApprovalConsumed {
			t.Fatalf("spend = %q, %v", code, err)
		}
		if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalAlreadyUsed {
			t.Fatalf("second spend = %q", code)
		}
		want := []string{AuditApprovalRequest, AuditApprovalApproved, AuditApprovalApproved, AuditApprovalConsumed}
		if strings.Join(rec.audits, ",") != strings.Join(want, ",") {
			t.Fatalf("audits = %v, want %v", rec.audits, want)
		}
		wantEvents := []string{EventApprovalPending, EventApprovalVote, EventApprovalApproved}
		if strings.Join(rec.types(), ",") != strings.Join(wantEvents, ",") {
			t.Fatalf("events = %v, want %v", rec.types(), wantEvents)
		}
		if ev := rec.events[1]; ev.RequiredApprovals != 2 || ev.ApprovalsReceived != 1 {
			t.Fatalf("vote event = %+v", ev)
		}
	})
	t.Run("arguments binding still holds", func(t *testing.T) {
		ap := quorumApprovals(&now, &recorder{}, 2)
		id, _ := ap.Open(ctx, call, esc)
		_ = decide(ap, id, "alice")
		_ = decide(ap, id, "bob")
		other := call
		other.Args = map[string]any{"speed": 500}
		if code, _ := ap.Spend(ctx, id, other); code != policy.CodeApprovalArgumentsMismatch {
			t.Fatalf("code = %q", code)
		}
	})
	t.Run("requester, agent and repeat approvers are refused", func(t *testing.T) {
		ap := quorumApprovals(&now, &recorder{}, 2)
		id, _ := ap.Open(ctx, call, esc)
		if err := decide(ap, id, "fleet-owner"); !errors.Is(err, ErrRequesterCannotApprove) {
			t.Fatalf("requester = %v", err)
		}
		if err := decide(ap, id, "robot-1"); !errors.Is(err, ErrRequesterCannotApprove) {
			t.Fatalf("agent = %v", err)
		}
		if err := decide(ap, id, "alice"); err != nil {
			t.Fatal(err)
		}
		if err := decide(ap, id, "alice"); !errors.Is(err, ErrDuplicateApprover) {
			t.Fatalf("repeat = %v", err)
		}
	})
	t.Run("a denial vetoes and expiry covers the quorum", func(t *testing.T) {
		ap := quorumApprovals(&now, &recorder{}, 2)
		id, _ := ap.Open(ctx, call, esc)
		_ = decide(ap, id, "alice")
		if _, err := ap.Decide(ctx, id, DecideInput{Decision: DecisionDeny, DecidedBy: "bob"}); err != nil {
			t.Fatal(err)
		}
		if err := decide(ap, id, "carol"); !errors.Is(err, ErrApprovalNotPending) {
			t.Fatalf("approve after deny = %v", err)
		}

		late := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		ap2 := quorumApprovals(&late, &recorder{}, 2)
		id2, _ := ap2.Open(ctx, call, esc)
		_ = decide(ap2, id2, "alice")
		late = late.Add(2 * time.Minute)
		if err := decide(ap2, id2, "bob"); !errors.Is(err, ErrApprovalExpired) {
			t.Fatalf("late vote = %v", err)
		}
		if code, _ := ap2.Spend(ctx, id2, call); code != policy.CodeApprovalExpired {
			t.Fatalf("spend after expiry = %q", code)
		}
	})
	t.Run("a quorum above the maximum is refused at open", func(t *testing.T) {
		ap := quorumApprovals(&now, &recorder{}, MaxRequiredApprovals+1)
		if _, err := ap.Open(ctx, call, esc); err == nil {
			t.Fatal("open accepted an oversized quorum")
		}
	})
}

func TestStorageApprovalsQuorumRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	call := Call{AgentID: "robot-1", Tool: "arm", Args: map[string]any{"speed": 5}}
	ap := NewStorageApprovals(memory.New(),
		WithApprovalQuorum(func(Call, policy.Escalation) int { return 2 }))
	id, _ := ap.Open(ctx, call, policy.Escalation{Requirement: policy.RequireApproval})

	var counted, dup atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := ap.Approve(ctx, id, "alice"); {
			case err == nil:
				counted.Add(1)
			case errors.Is(err, ErrDuplicateApprover):
				dup.Add(1)
			default:
				t.Errorf("unexpected error %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if counted.Load() != 1 || dup.Load() != 15 {
		t.Fatalf("counted %d, duplicates %d", counted.Load(), dup.Load())
	}
	if code, _ := ap.Spend(ctx, id, call); code != policy.CodeApprovalPending {
		t.Fatalf("one approver completed the quorum, code %q", code)
	}
}

package toolguard

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// voteQuorum counts approver's approval on a request that needs more than one approver. Each
// approval writes its own audit row (tool_approval.approved) with the quorum progress. The
// request is approved, and the approved event sent, only when the last approval lands. Until
// then the returned request still has a zero ApprovedAt and Spend answers approval_pending.
func (a *StorageApprovals) voteQuorum(ctx context.Context, admin theauth.ToolApprovalAdminStorage, cur theauth.ToolApproval, approver string, now time.Time) (theauth.ToolApproval, error) {
	q, ok := a.store.(theauth.ToolApprovalQuorumStorage)
	if !ok {
		return cur, ErrStoreUnsupported
	}
	if approver == cur.AgentID || (cur.OpenedBy != "" && approver == cur.OpenedBy) {
		return cur, ErrRequesterCannotApprove
	}
	vote, err := q.VoteToolApproval(ctx, cur.ID, approver, now)
	if err != nil {
		return cur, fmt.Errorf("toolguard: vote on approval %s: %w", cur.ID, err)
	}
	fresh, _, _ := admin.GetToolApproval(ctx, cur.ID)
	switch vote.Outcome {
	case theauth.VoteRequester:
		return fresh, ErrRequesterCannotApprove
	case theauth.VoteDuplicate:
		return fresh, ErrDuplicateApprover
	case theauth.VoteNotPending:
		if err := a.undecided(ctx, fresh, a.now().UTC()); err != nil {
			return fresh, err
		}
		return fresh, ErrApprovalNotPending
	}
	done := vote.Outcome == theauth.VoteCompleted
	a.recordWith(ctx, AuditApprovalApproved, fresh, approver, approver, map[string]any{
		"approvals_received": len(fresh.Approvers), "approvals_required": fresh.RequiredApprovals, "quorum_complete": done,
	})
	if done {
		a.emit(EventApprovalApproved, fresh, approver)
	} else {
		a.emit(EventApprovalVote, fresh, approver)
	}
	return fresh, nil
}

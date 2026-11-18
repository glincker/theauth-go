package sqlite

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.ToolApprovalQuorumStorage = (*Store)(nil)

// fillApprovers loads the approvers of a quorum request into a.
func (s *Store) fillApprovers(ctx context.Context, a *theauth.ToolApproval) error {
	if a.RequiredApprovals <= 1 {
		return nil
	}
	approvers, err := s.approversOf(ctx, a.ID)
	if err != nil {
		return err
	}
	a.Approvers = approvers
	return nil
}

func (s *Store) approversOf(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT approver FROM theauth_tool_approval_votes WHERE approval_id = ? ORDER BY voted_at ASC, approver ASC`), id)
	if err != nil {
		return nil, wrap("list tool approval votes", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var who string
		if err := rows.Scan(&who); err != nil {
			return nil, wrap("list tool approval votes", err)
		}
		out = append(out, who)
	}
	return out, wrap("list tool approval votes", rows.Err())
}

// VoteToolApproval implements theauth.ToolApprovalQuorumStorage with two conditional
// statements. The INSERT only lands while the request is live, undecided and not opened by the
// approver, and the primary key refuses a second vote from the same approver. The UPDATE
// approves the request only when the vote count has reached required_approvals, so one caller
// completes the quorum.
func (s *Store) VoteToolApproval(ctx context.Context, id, approver string, now time.Time) (theauth.ToolApprovalVote, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_tool_approval_votes (approval_id, approver, voted_at)
SELECT ?, ?, ? WHERE EXISTS (
  SELECT 1 FROM theauth_tool_approvals
  WHERE id = ? AND required_approvals > 1 AND approved_at IS NULL AND consumed_at IS NULL
    AND denied_at IS NULL AND expired_at IS NULL AND (expires_at = 0 OR expires_at > ?)
    AND (opened_by = '' OR opened_by <> ?))
ON CONFLICT (approval_id, approver) DO NOTHING`),
		id, approver, toMicro(now), id, toMicro(now), approver)
	counted, err := rowWon(res, err, "vote tool approval")
	if err != nil {
		return theauth.ToolApprovalVote{}, err
	}
	if !counted {
		return s.classifyRefusedVote(ctx, id, approver, now)
	}
	res, err = s.db.ExecContext(ctx, s.q(`
UPDATE theauth_tool_approvals SET approved_at = ?, approver = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND (expires_at = 0 OR expires_at > ?)
  AND (SELECT COUNT(*) FROM theauth_tool_approval_votes WHERE approval_id = ?) >= required_approvals`),
		toMicro(now), approver, id, toMicro(now), id)
	won, err := rowWon(res, err, "complete tool approval quorum")
	if err != nil {
		return theauth.ToolApprovalVote{}, err
	}
	cur, found, err := s.GetToolApproval(ctx, id)
	if err != nil {
		return theauth.ToolApprovalVote{}, err
	}
	outcome := theauth.VoteCounted
	switch {
	case won || (found && !cur.ApprovedAt.IsZero()):
		outcome = theauth.VoteCompleted
	case !found || !cur.DeniedAt.IsZero() || !cur.ExpiredAt.IsZero():
		outcome = theauth.VoteNotPending
	}
	return theauth.ToolApprovalVote{Outcome: outcome, Approvers: cur.Approvers}, nil
}

// classifyRefusedVote says why an INSERT changed no row.
func (s *Store) classifyRefusedVote(ctx context.Context, id, approver string, now time.Time) (theauth.ToolApprovalVote, error) {
	cur, found, err := s.GetToolApproval(ctx, id)
	if err != nil {
		return theauth.ToolApprovalVote{}, err
	}
	vote := theauth.ToolApprovalVote{Outcome: theauth.VoteNotPending, Approvers: cur.Approvers}
	live := found && cur.RequiredApprovals > 1 && cur.ApprovedAt.IsZero() && cur.ConsumedAt.IsZero() &&
		cur.DeniedAt.IsZero() && cur.ExpiredAt.IsZero() && (cur.ExpiresAt.IsZero() || cur.ExpiresAt.After(now))
	if !live {
		return vote, nil
	}
	if cur.OpenedBy != "" && cur.OpenedBy == approver {
		vote.Outcome = theauth.VoteRequester
		return vote, nil
	}
	for _, have := range cur.Approvers {
		if have == approver {
			vote.Outcome = theauth.VoteDuplicate
			return vote, nil
		}
	}
	return vote, nil
}

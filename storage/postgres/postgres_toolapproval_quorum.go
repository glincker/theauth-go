package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.ToolApprovalQuorumStorage = (*Store)(nil)

// fillApprovers loads the approvers of a quorum request into a.
func (s *Store) fillApprovers(ctx context.Context, a *theauth.ToolApproval) error {
	if a.RequiredApprovals <= 1 {
		return nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT approver FROM theauth_tool_approval_votes WHERE approval_id = $1 ORDER BY voted_at ASC, approver ASC`, a.ID)
	if err != nil {
		return fmt.Errorf("postgres: list tool approval votes: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var who string
		if err := rows.Scan(&who); err != nil {
			return fmt.Errorf("postgres: list tool approval votes: %w", err)
		}
		out = append(out, who)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: list tool approval votes: %w", err)
	}
	a.Approvers = out
	return nil
}

// VoteToolApproval implements theauth.ToolApprovalQuorumStorage with two conditional
// statements. The INSERT only lands while the request is live, undecided and not opened by the
// approver, and the primary key refuses a second vote from the same approver. The UPDATE
// approves the request only when the vote count has reached required_approvals, so one caller
// completes the quorum.
func (s *Store) VoteToolApproval(ctx context.Context, id, approver string, now time.Time) (theauth.ToolApprovalVote, error) {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO theauth_tool_approval_votes (approval_id, approver, voted_at)
SELECT $1, $2, $3 WHERE EXISTS (
  SELECT 1 FROM theauth_tool_approvals
  WHERE id = $1 AND required_approvals > 1 AND approved_at IS NULL AND consumed_at IS NULL
    AND denied_at IS NULL AND expired_at IS NULL AND (expires_at IS NULL OR expires_at > $3)
    AND (opened_by = '' OR opened_by <> $2))
ON CONFLICT (approval_id, approver) DO NOTHING`, id, approver, now.UTC())
	if err != nil {
		return theauth.ToolApprovalVote{}, fmt.Errorf("postgres: vote tool approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return s.classifyRefusedVote(ctx, id, approver, now)
	}
	tag, err = s.pool.Exec(ctx, `
UPDATE theauth_tool_approvals SET approved_at = $1, approver = $2
WHERE id = $3 AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND (expires_at IS NULL OR expires_at > $1)
  AND (SELECT COUNT(*) FROM theauth_tool_approval_votes WHERE approval_id = $3) >= required_approvals`,
		now.UTC(), approver, id)
	if err != nil {
		return theauth.ToolApprovalVote{}, fmt.Errorf("postgres: complete tool approval quorum: %w", err)
	}
	won := tag.RowsAffected() == 1
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

package sqlite

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.ToolApprovalStorage = (*Store)(nil)

func (s *Store) OpenToolApproval(ctx context.Context, a theauth.ToolApproval) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_tool_approvals (id, agent_id, action, resource, requirement, tier, reason, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.AgentID, a.Action, a.Resource, a.Requirement, a.Tier, a.Reason,
		toMicro(a.CreatedAt), throttleMicro(a.ExpiresAt))
	return wrap("open tool approval", err)
}

func (s *Store) ApproveToolApproval(ctx context.Context, id, approver string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_tool_approvals SET approved_at = ?, approver = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND (expires_at = 0 OR expires_at > ?)`),
		toMicro(now), approver, id, toMicro(now))
	return rowWon(res, err, "approve tool approval")
}

// ConsumeToolApproval implements theauth.ToolApprovalStorage. The conditional
// UPDATE is the single winner check: only one caller sees one affected row.
func (s *Store) ConsumeToolApproval(ctx context.Context, id, agentID, action, resource string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_tool_approvals SET consumed_at = ?
WHERE id = ? AND agent_id = ? AND action = ? AND resource = ?
  AND approved_at IS NOT NULL AND consumed_at IS NULL AND (expires_at = 0 OR expires_at > ?)`),
		toMicro(now), id, agentID, action, resource, toMicro(now))
	return rowWon(res, err, "consume tool approval")
}

func rowWon(res interface{ RowsAffected() (int64, error) }, err error, op string) (bool, error) {
	if err != nil {
		return false, wrap(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrap(op, err)
	}
	return n == 1, nil
}

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.ToolApprovalStorage = (*Store)(nil)

func toolApprovalExpiry(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

func oneRow(res sql.Result, err error, op string) (bool, error) {
	if err != nil {
		return false, fmt.Errorf("mysql: %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mysql: %s: %w", op, err)
	}
	return n == 1, nil
}

// OpenToolApproval implements theauth.ToolApprovalStorage.
func (s *Store) OpenToolApproval(ctx context.Context, a theauth.ToolApproval) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO theauth_tool_approvals (id, agent_id, action, resource, requirement, tier, reason, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AgentID, a.Action, a.Resource, a.Requirement, a.Tier, a.Reason,
		a.CreatedAt.UTC(), toolApprovalExpiry(a.ExpiresAt))
	if err != nil {
		return fmt.Errorf("mysql: open tool approval: %w", err)
	}
	return nil
}

// ApproveToolApproval implements theauth.ToolApprovalStorage.
func (s *Store) ApproveToolApproval(ctx context.Context, id, approver string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE theauth_tool_approvals SET approved_at = ?, approver = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		now.UTC(), approver, id, now.UTC())
	return oneRow(res, err, "approve tool approval")
}

// ConsumeToolApproval implements theauth.ToolApprovalStorage. The conditional
// UPDATE is the single winner check: only one caller sees one affected row.
// The DSN must not set clientFoundRows, which would count matched rows.
func (s *Store) ConsumeToolApproval(ctx context.Context, id, agentID, action, resource string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE theauth_tool_approvals SET consumed_at = ?
WHERE id = ? AND agent_id = ? AND action = ? AND resource = ?
  AND approved_at IS NOT NULL AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		now.UTC(), id, agentID, action, resource, now.UTC())
	return oneRow(res, err, "consume tool approval")
}

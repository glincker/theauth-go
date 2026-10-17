package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ theauth.ToolApprovalStorage = (*Store)(nil)

func nullableTime(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func (s *Store) OpenToolApproval(ctx context.Context, a theauth.ToolApproval) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO theauth_tool_approvals (id, agent_id, action, resource, requirement, tier, reason, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.ID, a.AgentID, a.Action, a.Resource, a.Requirement, a.Tier, a.Reason,
		a.CreatedAt.UTC(), nullableTime(a.ExpiresAt))
	if err != nil {
		return fmt.Errorf("postgres: open tool approval: %w", err)
	}
	return nil
}

func (s *Store) ApproveToolApproval(ctx context.Context, id, approver string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE theauth_tool_approvals SET approved_at = $1, approver = $2
WHERE id = $3 AND approved_at IS NULL AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > $1)`,
		now.UTC(), approver, id)
	if err != nil {
		return false, fmt.Errorf("postgres: approve tool approval: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeToolApproval implements theauth.ToolApprovalStorage. The conditional
// UPDATE is the single winner check: only one caller sees one affected row.
func (s *Store) ConsumeToolApproval(ctx context.Context, id, agentID, action, resource string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE theauth_tool_approvals SET consumed_at = $1
WHERE id = $2 AND agent_id = $3 AND action = $4 AND resource = $5
  AND approved_at IS NOT NULL AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > $1)`,
		now.UTC(), id, agentID, action, resource)
	if err != nil {
		return false, fmt.Errorf("postgres: consume tool approval: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

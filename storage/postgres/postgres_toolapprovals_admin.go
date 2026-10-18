package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const toolApprovalColumns = `id, agent_id, action, resource, requirement, tier, reason, approver, opened_by,
denied_by, arguments_hash, created_at, expires_at, approved_at, consumed_at, denied_at, expired_at`

func scanToolApproval(r pgx.Row) (theauth.ToolApproval, error) {
	var (
		a                                       theauth.ToolApproval
		expires, approved, consumed, denied, ex pgtype.Timestamptz
	)
	err := r.Scan(&a.ID, &a.AgentID, &a.Action, &a.Resource, &a.Requirement, &a.Tier, &a.Reason, &a.Approver,
		&a.OpenedBy, &a.DeniedBy, &a.ArgumentsHash, &a.CreatedAt, &expires, &approved, &consumed, &denied, &ex)
	if err != nil {
		return a, err
	}
	a.CreatedAt = a.CreatedAt.UTC()
	for _, p := range []struct {
		v   pgtype.Timestamptz
		dst *time.Time
	}{{expires, &a.ExpiresAt}, {approved, &a.ApprovedAt}, {consumed, &a.ConsumedAt}, {denied, &a.DeniedAt}, {ex, &a.ExpiredAt}} {
		if p.v.Valid {
			*p.dst = p.v.Time.UTC()
		}
	}
	return a, nil
}

// GetToolApproval implements theauth.ToolApprovalAdminStorage.
func (s *Store) GetToolApproval(ctx context.Context, id string) (theauth.ToolApproval, bool, error) {
	a, err := scanToolApproval(s.pool.QueryRow(ctx,
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return theauth.ToolApproval{}, false, nil
	}
	if err != nil {
		return theauth.ToolApproval{}, false, fmt.Errorf("postgres: get tool approval: %w", err)
	}
	return a, true, nil
}

func (s *Store) queryToolApprovals(ctx context.Context, op, query string, args ...any) ([]theauth.ToolApproval, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: %s: %w", op, err)
	}
	defer rows.Close()
	out := []theauth.ToolApproval{}
	for rows.Next() {
		a, err := scanToolApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: %s: %w", op, err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: %s: %w", op, err)
	}
	return out, nil
}

// ListToolApprovals implements theauth.ToolApprovalAdminStorage.
func (s *Store) ListToolApprovals(ctx context.Context, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals ORDER BY created_at DESC, id ASC LIMIT $1`, limit)
}

// DenyToolApproval implements theauth.ToolApprovalAdminStorage. The conditional UPDATE decides
// the winner, so a concurrent approve and deny produce exactly one success.
func (s *Store) DenyToolApproval(ctx context.Context, id, denier string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE theauth_tool_approvals SET denied_at = $1, denied_by = $2
WHERE id = $3 AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND (expires_at IS NULL OR expires_at > $1)`, now.UTC(), denier, id)
	if err != nil {
		return false, fmt.Errorf("postgres: deny tool approval: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ExpireToolApproval implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ExpireToolApproval(ctx context.Context, id string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE theauth_tool_approvals SET expired_at = $1
WHERE id = $2 AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at IS NOT NULL AND expires_at <= $1`, now.UTC(), id)
	if err != nil {
		return false, fmt.Errorf("postgres: expire tool approval: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListOverdueToolApprovals implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ListOverdueToolApprovals(ctx context.Context, now time.Time, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list overdue tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals
WHERE approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at IS NOT NULL AND expires_at <= $1 ORDER BY expires_at ASC, id ASC LIMIT $2`, now.UTC(), limit)
}

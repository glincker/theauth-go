package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

const toolApprovalColumns = `id, agent_id, action, resource, requirement, tier, reason, approver, opened_by,
denied_by, arguments_hash, created_at, expires_at, approved_at, consumed_at, denied_at, expired_at, required_approvals`

func scanToolApproval(r rowScanner) (theauth.ToolApproval, error) {
	var (
		a                                       theauth.ToolApproval
		expires, approved, consumed, denied, ex sql.NullTime
	)
	err := r.Scan(&a.ID, &a.AgentID, &a.Action, &a.Resource, &a.Requirement, &a.Tier, &a.Reason, &a.Approver,
		&a.OpenedBy, &a.DeniedBy, &a.ArgumentsHash, &a.CreatedAt, &expires, &approved, &consumed, &denied, &ex,
		&a.RequiredApprovals)
	if err != nil {
		return a, err
	}
	a.CreatedAt = a.CreatedAt.UTC()
	for _, p := range []struct {
		v   sql.NullTime
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
	a, err := scanToolApproval(s.db.QueryRowContext(ctx,
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return theauth.ToolApproval{}, false, nil
	}
	if err != nil {
		return theauth.ToolApproval{}, false, fmt.Errorf("mysql: get tool approval: %w", err)
	}
	if err := s.fillApprovers(ctx, &a); err != nil {
		return theauth.ToolApproval{}, false, err
	}
	return a, true, nil
}

func (s *Store) queryToolApprovals(ctx context.Context, op, query string, args ...any) ([]theauth.ToolApproval, error) {
	out, err := s.queryToolApprovalRows(ctx, op, query, args...)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fillApprovers(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) queryToolApprovalRows(ctx context.Context, op, query string, args ...any) ([]theauth.ToolApproval, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: %s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.ToolApproval{}
	for rows.Next() {
		a, err := scanToolApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql: %s: %w", op, err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: %s: %w", op, err)
	}
	return out, nil
}

// ListToolApprovals implements theauth.ToolApprovalAdminStorage.
func (s *Store) ListToolApprovals(ctx context.Context, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals ORDER BY created_at DESC, id ASC LIMIT ?`, limit)
}

// DenyToolApproval implements theauth.ToolApprovalAdminStorage. The conditional UPDATE decides
// the winner, so a concurrent approve and deny produce exactly one success.
func (s *Store) DenyToolApproval(ctx context.Context, id, denier string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE theauth_tool_approvals SET denied_at = ?, denied_by = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND (expires_at IS NULL OR expires_at > ?)`, now.UTC(), denier, id, now.UTC())
	return oneRow(res, err, "deny tool approval")
}

// ExpireToolApproval implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ExpireToolApproval(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE theauth_tool_approvals SET expired_at = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at IS NOT NULL AND expires_at <= ?`, now.UTC(), id, now.UTC())
	return oneRow(res, err, "expire tool approval")
}

// ListOverdueToolApprovals implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ListOverdueToolApprovals(ctx context.Context, now time.Time, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list overdue tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals
WHERE approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at ASC, id ASC LIMIT ?`, now.UTC(), limit)
}

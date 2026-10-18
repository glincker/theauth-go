package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2"
)

const toolApprovalColumns = `id, agent_id, action, resource, requirement, tier, reason, approver, opened_by,
denied_by, arguments_hash, created_at, expires_at, approved_at, consumed_at, denied_at, expired_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanToolApproval(r rowScanner) (theauth.ToolApproval, error) {
	var (
		a                                          theauth.ToolApproval
		created, expires                           int64
		approved, consumed, denied, expiredAtMicro sql.NullInt64
	)
	err := r.Scan(&a.ID, &a.AgentID, &a.Action, &a.Resource, &a.Requirement, &a.Tier, &a.Reason, &a.Approver,
		&a.OpenedBy, &a.DeniedBy, &a.ArgumentsHash, &created, &expires, &approved, &consumed, &denied, &expiredAtMicro)
	if err != nil {
		return a, err
	}
	a.CreatedAt = fromMicro(created)
	a.ExpiresAt = throttleTime(expires)
	for _, p := range []struct {
		v   sql.NullInt64
		dst *time.Time
	}{{approved, &a.ApprovedAt}, {consumed, &a.ConsumedAt}, {denied, &a.DeniedAt}, {expiredAtMicro, &a.ExpiredAt}} {
		if p.v.Valid {
			*p.dst = fromMicro(p.v.Int64)
		}
	}
	return a, nil
}

// GetToolApproval implements theauth.ToolApprovalAdminStorage.
func (s *Store) GetToolApproval(ctx context.Context, id string) (theauth.ToolApproval, bool, error) {
	a, err := scanToolApproval(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return theauth.ToolApproval{}, false, nil
	}
	return a, err == nil, wrap("get tool approval", err)
}

// ListToolApprovals implements theauth.ToolApprovalAdminStorage.
func (s *Store) ListToolApprovals(ctx context.Context, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals ORDER BY created_at DESC, id ASC LIMIT ?`, limit)
}

func (s *Store) queryToolApprovals(ctx context.Context, op, query string, args ...any) ([]theauth.ToolApproval, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, wrap(op, err)
	}
	defer rows.Close()
	out := []theauth.ToolApproval{}
	for rows.Next() {
		a, err := scanToolApproval(rows)
		if err != nil {
			return nil, wrap(op, err)
		}
		out = append(out, a)
	}
	return out, wrap(op, rows.Err())
}

// DenyToolApproval implements theauth.ToolApprovalAdminStorage. The conditional UPDATE decides
// the winner, so a concurrent approve and deny produce exactly one success.
func (s *Store) DenyToolApproval(ctx context.Context, id, denier string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_tool_approvals SET denied_at = ?, denied_by = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND (expires_at = 0 OR expires_at > ?)`),
		toMicro(now), denier, id, toMicro(now))
	return rowWon(res, err, "deny tool approval")
}

// ExpireToolApproval implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ExpireToolApproval(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_tool_approvals SET expired_at = ?
WHERE id = ? AND approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at > 0 AND expires_at <= ?`),
		toMicro(now), id, toMicro(now))
	return rowWon(res, err, "expire tool approval")
}

// ListOverdueToolApprovals implements theauth.ToolApprovalExpiryStorage.
func (s *Store) ListOverdueToolApprovals(ctx context.Context, now time.Time, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.queryToolApprovals(ctx, "list overdue tool approvals",
		`SELECT `+toolApprovalColumns+` FROM theauth_tool_approvals
WHERE approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL
  AND expires_at > 0 AND expires_at <= ? ORDER BY expires_at ASC, id ASC LIMIT ?`, toMicro(now), limit)
}

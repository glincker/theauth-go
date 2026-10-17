package memory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var (
	_ theauth.ToolApprovalStorage      = (*Store)(nil)
	_ theauth.ToolApprovalAdminStorage = (*Store)(nil)
)

func (s *Store) OpenToolApproval(_ context.Context, a theauth.ToolApproval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toolApprovals == nil {
		s.toolApprovals = map[string]theauth.ToolApproval{}
	}
	if _, dup := s.toolApprovals[a.ID]; dup {
		return fmt.Errorf("memory: tool approval %s already exists", a.ID)
	}
	s.toolApprovals[a.ID] = a
	return nil
}

func toolApprovalLive(a theauth.ToolApproval, now time.Time) bool {
	return a.ConsumedAt.IsZero() && a.DeniedAt.IsZero() && (a.ExpiresAt.IsZero() || a.ExpiresAt.After(now))
}

func (s *Store) ApproveToolApproval(_ context.Context, id, approver string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || !a.ApprovedAt.IsZero() || !toolApprovalLive(a, now) {
		return false, nil
	}
	a.ApprovedAt, a.Approver = now, approver
	s.toolApprovals[id] = a
	return true, nil
}

func (s *Store) ConsumeToolApproval(_ context.Context, id, agentID, action, resource string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || a.ApprovedAt.IsZero() || !toolApprovalLive(a, now) {
		return false, nil
	}
	if a.AgentID != agentID || a.Action != action || a.Resource != resource {
		return false, nil
	}
	a.ConsumedAt = now
	s.toolApprovals[id] = a
	return true, nil
}

func (s *Store) GetToolApproval(_ context.Context, id string) (theauth.ToolApproval, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	return a, ok, nil
}

func (s *Store) ListToolApprovals(_ context.Context, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	out := make([]theauth.ToolApproval, 0, len(s.toolApprovals))
	for _, a := range s.toolApprovals {
		out = append(out, a)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) DenyToolApproval(_ context.Context, id, denier string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || !a.ApprovedAt.IsZero() || !toolApprovalLive(a, now) {
		return false, nil
	}
	a.DeniedAt, a.DeniedBy = now, denier
	s.toolApprovals[id] = a
	return true, nil
}

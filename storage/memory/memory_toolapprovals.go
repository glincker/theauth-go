package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var _ theauth.ToolApprovalStorage = (*Store)(nil)

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
	return a.ConsumedAt.IsZero() && (a.ExpiresAt.IsZero() || a.ExpiresAt.After(now))
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

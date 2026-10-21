package memory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
)

var (
	_ theauth.ToolApprovalStorage       = (*Store)(nil)
	_ theauth.ToolApprovalAdminStorage  = (*Store)(nil)
	_ theauth.ToolApprovalExpiryStorage = (*Store)(nil)
	_ theauth.ToolApprovalQuorumStorage = (*Store)(nil)
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
	a.Approvers = nil
	s.toolApprovals[a.ID] = a
	return nil
}

func toolApprovalLive(a theauth.ToolApproval, now time.Time) bool {
	return a.ConsumedAt.IsZero() && a.DeniedAt.IsZero() && a.ExpiredAt.IsZero() && (a.ExpiresAt.IsZero() || a.ExpiresAt.After(now))
}

func (s *Store) ApproveToolApproval(_ context.Context, id, approver string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || !a.ApprovedAt.IsZero() || !toolApprovalLive(a, now) || a.RequiredApprovals > 1 {
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
	return copyApprovers(a), ok, nil
}

// copyApprovers returns a with its own Approvers slice, so a caller cannot edit the stored one.
func copyApprovers(a theauth.ToolApproval) theauth.ToolApproval {
	if a.Approvers != nil {
		a.Approvers = append([]string(nil), a.Approvers...)
	}
	return a
}

// VoteToolApproval implements theauth.ToolApprovalQuorumStorage under the store mutex.
func (s *Store) VoteToolApproval(_ context.Context, id, approver string, now time.Time) (theauth.ToolApprovalVote, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || a.RequiredApprovals <= 1 || !a.ApprovedAt.IsZero() || !toolApprovalLive(a, now) {
		return theauth.ToolApprovalVote{Outcome: theauth.VoteNotPending, Approvers: append([]string(nil), a.Approvers...)}, nil
	}
	if a.OpenedBy != "" && a.OpenedBy == approver {
		return theauth.ToolApprovalVote{Outcome: theauth.VoteRequester, Approvers: append([]string(nil), a.Approvers...)}, nil
	}
	for _, have := range a.Approvers {
		if have == approver {
			return theauth.ToolApprovalVote{Outcome: theauth.VoteDuplicate, Approvers: append([]string(nil), a.Approvers...)}, nil
		}
	}
	a.Approvers = append(append([]string(nil), a.Approvers...), approver)
	outcome := theauth.VoteCounted
	if len(a.Approvers) >= a.RequiredApprovals {
		a.ApprovedAt, a.Approver = now, approver
		outcome = theauth.VoteCompleted
	}
	s.toolApprovals[id] = a
	return theauth.ToolApprovalVote{Outcome: outcome, Approvers: append([]string(nil), a.Approvers...)}, nil
}

func (s *Store) ListToolApprovals(_ context.Context, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	out := make([]theauth.ToolApproval, 0, len(s.toolApprovals))
	for _, a := range s.toolApprovals {
		out = append(out, copyApprovers(a))
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

func toolApprovalOverdue(a theauth.ToolApproval, now time.Time) bool {
	return a.ApprovedAt.IsZero() && a.DeniedAt.IsZero() && a.ConsumedAt.IsZero() && a.ExpiredAt.IsZero() &&
		!a.ExpiresAt.IsZero() && !a.ExpiresAt.After(now)
}

func (s *Store) ExpireToolApproval(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.toolApprovals[id]
	if !ok || !toolApprovalOverdue(a, now) {
		return false, nil
	}
	a.ExpiredAt = now
	s.toolApprovals[id] = a
	return true, nil
}

func (s *Store) ListOverdueToolApprovals(_ context.Context, now time.Time, limit int) ([]theauth.ToolApproval, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	out := make([]theauth.ToolApproval, 0)
	for _, a := range s.toolApprovals {
		if toolApprovalOverdue(a, now) {
			out = append(out, a)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].ExpiresAt.Before(out[j].ExpiresAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

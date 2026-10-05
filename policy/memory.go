package policy

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process Storage for tests and single-node setups.
type Memory struct {
	mu       sync.RWMutex
	policies map[string]Record
	attached map[Subject]map[string]struct{}
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory {
	return &Memory{policies: map[string]Record{}, attached: map[Subject]map[string]struct{}{}}
}

func cloneRecord(r Record) Record {
	r.Document = slices.Clone(r.Document)
	return r
}

// PutPolicy upserts a policy after validating its document.
func (m *Memory) PutPolicy(_ context.Context, r Record) error {
	if r.ID == "" {
		return fmt.Errorf("policy: put: empty id")
	}
	if _, err := Parse(r.Document); err != nil {
		return fmt.Errorf("policy: put %q: %w", r.ID, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	r = cloneRecord(r)
	r.UpdatedAt = now
	if old, ok := m.policies[r.ID]; ok {
		r.CreatedAt = old.CreatedAt
	} else {
		r.CreatedAt = now
	}
	m.policies[r.ID] = r
	return nil
}

// GetPolicy returns one policy or ErrNotFound.
func (m *Memory) GetPolicy(_ context.Context, id string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.policies[id]
	if !ok {
		return nil, ErrNotFound
	}
	r = cloneRecord(r)
	return &r, nil
}

// ListPolicies returns all policies ordered by ID.
func (m *Memory) ListPolicies(_ context.Context) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Record, 0, len(m.policies))
	for _, r := range m.policies {
		out = append(out, cloneRecord(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeletePolicy removes a policy and its attachments.
func (m *Memory) DeletePolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, id)
	for s, set := range m.attached {
		delete(set, id)
		if len(set) == 0 {
			delete(m.attached, s)
		}
	}
	return nil
}

// AttachPolicy attaches an existing policy to a subject.
func (m *Memory) AttachPolicy(_ context.Context, s Subject, policyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[policyID]; !ok {
		return ErrNotFound
	}
	if m.attached[s] == nil {
		m.attached[s] = map[string]struct{}{}
	}
	m.attached[s][policyID] = struct{}{}
	return nil
}

// DetachPolicy removes an attachment, if present.
func (m *Memory) DetachPolicy(_ context.Context, s Subject, policyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attached[s], policyID)
	if len(m.attached[s]) == 0 {
		delete(m.attached, s)
	}
	return nil
}

// PoliciesFor returns the policies attached to any of the subjects.
func (m *Memory) PoliciesFor(_ context.Context, subjects []Subject) ([]Attached, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Attached
	seen := map[Subject]bool{}
	for _, s := range subjects {
		if seen[s] {
			continue
		}
		seen[s] = true
		for id := range m.attached[s] {
			out = append(out, Attached{Subject: s, Record: cloneRecord(m.policies[id])})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Record.ID != b.Record.ID {
			return a.Record.ID < b.Record.ID
		}
		if a.Subject.Kind != b.Subject.Kind {
			return a.Subject.Kind < b.Subject.Kind
		}
		return a.Subject.ID < b.Subject.ID
	})
	return out, nil
}

var _ Storage = (*Memory)(nil)

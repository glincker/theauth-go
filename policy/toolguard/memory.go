package toolguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/glincker/theauth-go/v2/policy"
)

type memRequest struct {
	agentID, action, resource string
	approved, spent           bool
	approver                  string
}

// MemoryApprovals is an in-process Approvals for tests and single-node hosts.
// A multi-node host needs a shared store with the same single-use rule.
type MemoryApprovals struct {
	mu   sync.Mutex
	reqs map[string]*memRequest
}

// NewMemoryApprovals returns an empty store.
func NewMemoryApprovals() *MemoryApprovals {
	return &MemoryApprovals{reqs: map[string]*memRequest{}}
}

// Open implements Approvals.
func (m *MemoryApprovals) Open(_ context.Context, c Call, _ policy.Escalation) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("toolguard: generate approval id: %w", err)
	}
	id := hex.EncodeToString(b[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqs[id] = &memRequest{agentID: c.AgentID, action: c.action(), resource: c.resource()}
	return id, nil
}

// Approve marks a pending request approved by approver.
func (m *MemoryApprovals) Approve(id, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return fmt.Errorf("toolguard: approval %s not found", id)
	}
	r.approved, r.approver = true, approver
	return nil
}

// Consume implements Approvals.
func (m *MemoryApprovals) Consume(_ context.Context, id string, c Call) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok || !r.approved || r.spent {
		return false, nil
	}
	if r.agentID != c.AgentID || r.action != c.action() || r.resource != c.resource() {
		return false, nil
	}
	r.spent = true
	return true, nil
}

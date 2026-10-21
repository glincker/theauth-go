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
	agentID, action, resource, argsHash string
	approved, spent, denied             bool
	approver                            string
}

var _ Spender = (*MemoryApprovals)(nil)

// MemoryApprovals is an in-process Approvals for tests and single-node hosts. It binds an id to
// the agent, action, resource and arguments of the call it was opened for, like StorageApprovals,
// but requests never expire. A multi-node host uses NewStorageApprovals over a shared store.
type MemoryApprovals struct {
	mu   sync.Mutex
	reqs map[string]*memRequest
}

// NewMemoryApprovals returns an empty store.
func NewMemoryApprovals() *MemoryApprovals {
	return &MemoryApprovals{reqs: map[string]*memRequest{}}
}

// Open implements Approvals. It fails closed when the call arguments cannot be hashed.
func (m *MemoryApprovals) Open(_ context.Context, c Call, _ policy.Escalation) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("toolguard: generate approval id: %w", err)
	}
	hash, err := HashApprovalAction(c.action(), c.resource(), c.Args)
	if err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqs[id] = &memRequest{agentID: c.AgentID, action: c.action(), resource: c.resource(), argsHash: hash}
	return id, nil
}

// Approve marks a pending request approved by approver. It returns an error for an unknown id
// and for one that is already denied or spent.
func (m *MemoryApprovals) Approve(id, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return fmt.Errorf("toolguard: approval %s not found", id)
	}
	if r.denied || r.spent {
		return fmt.Errorf("toolguard: approval %s is not pending", id)
	}
	r.approved, r.approver = true, approver
	return nil
}

// Deny marks a pending request denied. It returns an error for an unknown id and for one that is
// already approved, denied or spent.
func (m *MemoryApprovals) Deny(id, denier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return fmt.Errorf("toolguard: approval %s not found", id)
	}
	if r.approved || r.denied || r.spent {
		return fmt.Errorf("toolguard: approval %s is not pending", id)
	}
	r.denied, r.approver = true, denier
	return nil
}

// Consume implements Approvals.
func (m *MemoryApprovals) Consume(ctx context.Context, id string, c Call) (bool, error) {
	code, err := m.Spend(ctx, id, c)
	return code == policy.CodeApprovalConsumed, err
}

// Spend implements Spender.
func (m *MemoryApprovals) Spend(_ context.Context, id string, c Call) (policy.DecisionCode, error) {
	presented, presentedErr := HashApprovalAction(c.action(), c.resource(), c.Args)
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	switch {
	case !ok:
		return policy.CodeApprovalNotFound, nil
	case r.agentID != c.AgentID || r.action != c.action() || r.resource != c.resource():
		return policy.CodeApprovalMismatch, nil
	case r.denied:
		return policy.CodeApprovalDenied, nil
	case !r.approved:
		return policy.CodeApprovalPending, nil
	case r.spent:
		return policy.CodeApprovalAlreadyUsed, nil
	case presentedErr != nil || presented != r.argsHash:
		return policy.CodeApprovalArgumentsMismatch, nil
	}
	r.spent = true
	return policy.CodeApprovalConsumed, nil
}

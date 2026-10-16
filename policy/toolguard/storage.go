package toolguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
)

// DefaultApprovalTTL is how long a StorageApprovals request stays approvable
// and spendable when WithApprovalTTL is not set.
const DefaultApprovalTTL = time.Hour

var _ Approvals = (*StorageApprovals)(nil)

// StorageApprovals is an Approvals backed by a theauth.ToolApprovalStorage, so
// an approval opened on one node can be approved and spent once on any node.
// Like MemoryApprovals, an id is bound to the agent, action and resource of
// the call it was opened for.
type StorageApprovals struct {
	store theauth.ToolApprovalStorage
	ttl   time.Duration
	now   func() time.Time
}

// StorageApprovalsOption configures NewStorageApprovals.
type StorageApprovalsOption func(*StorageApprovals)

// WithApprovalTTL sets how long a request lives. Zero or negative means it
// never expires.
func WithApprovalTTL(d time.Duration) StorageApprovalsOption {
	return func(a *StorageApprovals) { a.ttl = d }
}

// WithApprovalClock replaces the clock, for tests.
func WithApprovalClock(now func() time.Time) StorageApprovalsOption {
	return func(a *StorageApprovals) { a.now = now }
}

// NewStorageApprovals returns an Approvals over store. Use the sqlite,
// postgres, mysql or memory Store, all of which implement the capability.
func NewStorageApprovals(store theauth.ToolApprovalStorage, opts ...StorageApprovalsOption) *StorageApprovals {
	a := &StorageApprovals{store: store, ttl: DefaultApprovalTTL, now: time.Now}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Open implements Approvals.
func (a *StorageApprovals) Open(ctx context.Context, c Call, e policy.Escalation) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("toolguard: generate approval id: %w", err)
	}
	now := a.now().UTC()
	req := theauth.ToolApproval{
		ID: hex.EncodeToString(b[:]), AgentID: c.AgentID, Action: c.action(), Resource: c.resource(),
		Requirement: string(e.Requirement), Tier: e.Tier, Reason: e.Reason, CreatedAt: now,
	}
	if a.ttl > 0 {
		req.ExpiresAt = now.Add(a.ttl)
	}
	if err := a.store.OpenToolApproval(ctx, req); err != nil {
		return "", fmt.Errorf("toolguard: open approval: %w", err)
	}
	return req.ID, nil
}

// Approve marks a pending request approved by approver. It returns an error
// when the request is unknown, expired, already approved or already spent.
func (a *StorageApprovals) Approve(ctx context.Context, id, approver string) error {
	ok, err := a.store.ApproveToolApproval(ctx, id, approver, a.now().UTC())
	if err != nil {
		return fmt.Errorf("toolguard: approve %s: %w", id, err)
	}
	if !ok {
		return fmt.Errorf("toolguard: approval %s is not pending", id)
	}
	return nil
}

// Consume implements Approvals. The store decides the winner atomically, so
// concurrent callers across nodes get true at most once.
func (a *StorageApprovals) Consume(ctx context.Context, id string, c Call) (bool, error) {
	ok, err := a.store.ConsumeToolApproval(ctx, id, c.AgentID, c.action(), c.resource(), a.now().UTC())
	if err != nil {
		return false, fmt.Errorf("toolguard: consume approval %s: %w", id, err)
	}
	return ok, nil
}

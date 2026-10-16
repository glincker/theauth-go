package theauth

import (
	"context"
	"time"
)

// ToolApproval is one approval request for a guarded agent tool call. It is
// bound to the agent, action and resource it was opened for.
type ToolApproval struct {
	ID       string
	AgentID  string
	Action   string
	Resource string
	// Requirement, Tier and Reason describe why the call escalated.
	Requirement string
	Tier        string
	Reason      string
	// Approver is set once a human approves the request.
	Approver  string
	CreatedAt time.Time
	// ExpiresAt is the zero time when the request never expires.
	ExpiresAt  time.Time
	ApprovedAt time.Time
	ConsumedAt time.Time
}

// ToolApprovalStorage is the optional storage capability behind single use
// approvals for agent tool calls (policy/toolguard.NewStorageApprovals). A
// store shared by every node makes an approval spendable exactly once across
// the whole deployment.
//
// A backend implements it by satisfying these methods on its Store. The
// consume step must be one atomic conditional write, for example
// UPDATE ... SET consumed_at = ? WHERE id = ? AND approved_at IS NOT NULL AND
// consumed_at IS NULL, with the rows affected count deciding the winner.
type ToolApprovalStorage interface {
	// OpenToolApproval records a pending request. a.ID must be unique.
	OpenToolApproval(ctx context.Context, a ToolApproval) error
	// ApproveToolApproval marks a pending, unexpired, unspent request approved
	// by approver. It reports false when no such request is pending.
	ApproveToolApproval(ctx context.Context, id, approver string, now time.Time) (bool, error)
	// ConsumeToolApproval spends id when it is approved, unexpired, unspent and
	// was opened for the same agent, action and resource. It reports false
	// otherwise. A given id returns true at most once.
	ConsumeToolApproval(ctx context.Context, id, agentID, action, resource string, now time.Time) (bool, error)
}

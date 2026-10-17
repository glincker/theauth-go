package theauth

import (
	"context"
	"time"
)

// ToolApproval is one approval request for a guarded agent tool call, bound to the agent, action
// and resource it was opened for.
type ToolApproval struct {
	ID          string
	AgentID     string
	Action      string
	Resource    string
	Requirement string
	Tier        string
	Reason      string
	Approver    string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ApprovedAt  time.Time
	ConsumedAt  time.Time
}

// ToolApprovalStorage is the optional storage capability behind single-use approvals for agent tool
// calls. The consume step must be one atomic conditional write (for example UPDATE ... WHERE
// consumed_at IS NULL, deciding the winner by rows affected), so an approval is spent exactly once
// across the deployment.
type ToolApprovalStorage interface {
	OpenToolApproval(ctx context.Context, a ToolApproval) error
	ApproveToolApproval(ctx context.Context, id, approver string, now time.Time) (bool, error)
	// ConsumeToolApproval spends id when it is approved, unexpired, unspent and opened for the same
	// agent, action and resource.
	ConsumeToolApproval(ctx context.Context, id, agentID, action, resource string, now time.Time) (bool, error)
}

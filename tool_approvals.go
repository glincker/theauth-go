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
	// OpenedBy is the human or service that opened the request, used for the four-eyes check in
	// the approvals package. Empty means unknown, so no self-approval check applies.
	OpenedBy   string
	DeniedBy   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ApprovedAt time.Time
	ConsumedAt time.Time
	DeniedAt   time.Time
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

// ToolApprovalAdminStorage is the optional capability behind the approvals inbox
// (the approvals package). Only the memory store implements it today; SQL backends do not.
// A store that implements it must make ApproveToolApproval fail for a denied request, and
// DenyToolApproval must be one atomic conditional write deciding the winner by rows affected.
type ToolApprovalAdminStorage interface {
	ToolApprovalStorage
	GetToolApproval(ctx context.Context, id string) (ToolApproval, bool, error)
	// ListToolApprovals returns requests created newest first, at most limit (0 means 100).
	ListToolApprovals(ctx context.Context, limit int) ([]ToolApproval, error)
	// DenyToolApproval denies id when it is still undecided, unspent and unexpired.
	DenyToolApproval(ctx context.Context, id, denier string, now time.Time) (bool, error)
}

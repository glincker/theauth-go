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
	OpenedBy string
	DeniedBy string
	// ArgumentsHash binds the request to the arguments the approver saw: a hex SHA-256 of the
	// canonical JSON of action, resource and arguments (toolguard.HashApprovalAction). It is never
	// edited after the request is opened. Empty means the request is not argument bound (a row
	// opened before the column existed), which any presented arguments satisfy.
	ArgumentsHash string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ApprovedAt    time.Time
	ConsumedAt    time.Time
	DeniedAt      time.Time
	// ExpiredAt is set once by ExpireToolApproval, the first time an overdue undecided request
	// is noticed. Expiry is also derived from ExpiresAt, so a request past ExpiresAt is expired
	// whether or not this is set.
	ExpiredAt time.Time
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
// (the approvals package). Every built in store implements it.
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

// ToolApprovalExpiryStorage is the optional capability that marks overdue requests expired, so
// the expiry is recorded once (one audit row, one event). Every built in store implements it.
type ToolApprovalExpiryStorage interface {
	// ExpireToolApproval flips id to expired when it is undecided, unspent, not yet marked and past
	// its ExpiresAt. Exactly one concurrent caller sees true.
	ExpireToolApproval(ctx context.Context, id string, now time.Time) (bool, error)
	// ListOverdueToolApprovals returns undecided, unmarked requests past ExpiresAt, oldest first,
	// at most limit (0 means 100).
	ListOverdueToolApprovals(ctx context.Context, now time.Time, limit int) ([]ToolApproval, error)
}

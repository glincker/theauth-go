package toolguard

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
)

// Spender is an Approvals that can say why a spend failed. Guard prefers it over Consume: on a
// failed spend the error carries the returned approval_* code instead of the generic
// approval_invalid.
type Spender interface {
	Approvals
	// Spend returns policy.CodeApprovalConsumed when the approval was spent, or the code that
	// says why it could not be: approval_not_found, approval_pending, approval_denied,
	// approval_expired, approval_already_used, approval_mismatch or
	// approval_arguments_mismatch. An error means the check itself failed.
	Spend(ctx context.Context, id string, c Call) (policy.DecisionCode, error)
}

// classifyApproval returns the denial code for ap and the call, or "" when the approval can be
// spent. The order matches the TypeScript library: binding first (agent, action, resource), then
// the settled states, then arguments last. Stored arguments are never edited, so the arguments
// check cannot drift between this read and the conditional write that spends the approval.
func classifyApproval(ap theauth.ToolApproval, found bool, c Call, presented string, presentedErr error, now time.Time) policy.DecisionCode {
	overdue := !ap.ExpiresAt.IsZero() && !ap.ExpiresAt.After(now)
	switch {
	case !found:
		return policy.CodeApprovalNotFound
	case ap.AgentID != c.AgentID || ap.Action != c.action() || ap.Resource != c.resource():
		return policy.CodeApprovalMismatch
	case !ap.DeniedAt.IsZero():
		return policy.CodeApprovalDenied
	case !ap.ExpiredAt.IsZero():
		return policy.CodeApprovalExpired
	case ap.ApprovedAt.IsZero():
		// A request nobody answered in time is expired, not pending.
		if overdue {
			return policy.CodeApprovalExpired
		}
		return policy.CodeApprovalPending
	case !ap.ConsumedAt.IsZero():
		return policy.CodeApprovalAlreadyUsed
	case overdue:
		return policy.CodeApprovalExpired
	}
	// An empty stored hash is a request opened before arguments were bound: it covers any call.
	if ap.ArgumentsHash != "" && (presentedErr != nil || presented != ap.ArgumentsHash) {
		return policy.CodeApprovalArgumentsMismatch
	}
	return ""
}

// Spend implements Spender. It reads the request to choose a denial code, then spends it with
// one conditional write in the store. Success means that write changed a row, so two concurrent
// callers cannot both win. The read only chooses the code.
func (a *StorageApprovals) Spend(ctx context.Context, id string, c Call) (policy.DecisionCode, error) {
	now := a.now().UTC()
	admin, canRead := a.store.(theauth.ToolApprovalAdminStorage)
	if !canRead {
		ok, err := a.store.ConsumeToolApproval(ctx, id, c.AgentID, c.action(), c.resource(), now)
		if err != nil {
			return "", fmt.Errorf("toolguard: consume approval %s: %w", id, err)
		}
		if ok {
			return policy.CodeApprovalConsumed, nil
		}
		return policy.CodeApprovalInvalid, nil
	}
	presented, presentedErr := HashApprovalAction(c.action(), c.resource(), c.Args)
	ap, found, err := admin.GetToolApproval(ctx, id)
	if err != nil {
		return "", fmt.Errorf("toolguard: load approval %s: %w", id, err)
	}
	if code := classifyApproval(ap, found, c, presented, presentedErr, now); code != "" {
		if code == policy.CodeApprovalExpired {
			a.markExpired(ctx, ap, now)
		}
		return code, nil
	}
	won, err := a.store.ConsumeToolApproval(ctx, id, c.AgentID, c.action(), c.resource(), now)
	if err != nil {
		return "", fmt.Errorf("toolguard: consume approval %s: %w", id, err)
	}
	if !won {
		// Lost a race or the row changed under us. Say why, never allow.
		fresh, ok, err := admin.GetToolApproval(ctx, id)
		if err != nil {
			return "", fmt.Errorf("toolguard: reload approval %s: %w", id, err)
		}
		if code := classifyApproval(fresh, ok, c, presented, presentedErr, a.now().UTC()); code != "" {
			return code, nil
		}
		return policy.CodeApprovalAlreadyUsed, nil
	}
	ap.ConsumedAt = now
	approver := ap.Approver
	a.record(ctx, AuditApprovalConsumed, ap, c.AgentID, approver)
	return policy.CodeApprovalConsumed, nil
}

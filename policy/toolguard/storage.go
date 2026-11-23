package toolguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
)

// DefaultApprovalTTL is how long a StorageApprovals request stays approvable
// and spendable when WithApprovalTTL is not set.
const DefaultApprovalTTL = time.Hour

var (
	_ Approvals = (*StorageApprovals)(nil)
	_ Spender   = (*StorageApprovals)(nil)
)

// StorageApprovals is an Approvals backed by a theauth.ToolApprovalStorage, so
// an approval opened on one node can be approved and spent once on any node.
// An id is bound to the agent, action, resource and arguments of the call it
// was opened for. A store that also implements theauth.ToolApprovalAdminStorage
// (every built in store does) lets Spend say why a spend failed with a specific
// approval_* decision code, and lets Decide approve or deny.
type StorageApprovals struct {
	store   theauth.ToolApprovalStorage
	ttl     time.Duration
	now     func() time.Time
	audit   AuditFunc
	onEvent func(ApprovalEvent)
	quorum  func(Call, policy.Escalation) int
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

// WithApprovalAudit writes one audit row per step: approval.request when a request opens,
// tool_approval.approved, tool_approval.denied, tool_approval.expired and
// tool_approval.consumed. The method value (*theauth.TheAuth).EmitAudit fits. The deciding human
// is the row's approver, the agent is its subject.
func WithApprovalAudit(fn AuditFunc) StorageApprovalsOption {
	return func(a *StorageApprovals) { a.audit = fn }
}

// WithApprovalEvents sets a sink that sees every lifecycle event (approval.pending,
// approval.approved, approval.denied, approval.expired). It runs on the caller's goroutine and
// must not block: hand slow work to a goroutine, or use NewApprovalWebhook. A panic in the sink
// is recovered and logged.
func WithApprovalEvents(fn func(ApprovalEvent)) StorageApprovalsOption {
	return func(a *StorageApprovals) { a.onEvent = fn }
}

// MaxRequiredApprovals is the largest quorum WithApprovalQuorum accepts.
const MaxRequiredApprovals = 10

// WithApprovalQuorum sets how many distinct approvers a request needs, chosen per call, for
// example two for a dangerous robot command and one for everything else. A result below 1 reads
// as 1. A result above MaxRequiredApprovals makes Open fail, because a quorum that large is almost
// always a mistake. The default is one approver, which is the ordinary flow.
func WithApprovalQuorum(fn func(Call, policy.Escalation) int) StorageApprovalsOption {
	return func(a *StorageApprovals) { a.quorum = fn }
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

// Open implements Approvals. It fails closed when the call arguments cannot be hashed, because
// an approval that cannot be bound to its arguments must not be spendable.
func (a *StorageApprovals) Open(ctx context.Context, c Call, e policy.Escalation) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("toolguard: generate approval id: %w", err)
	}
	hash, err := HashApprovalAction(c.action(), c.resource(), c.Args)
	if err != nil {
		return "", err
	}
	now := a.now().UTC()
	required := 1
	if a.quorum != nil {
		required = max(a.quorum(c, e), 1)
	}
	if required > MaxRequiredApprovals {
		return "", fmt.Errorf("toolguard: quorum of %d is above the maximum of %d", required, MaxRequiredApprovals)
	}
	req := theauth.ToolApproval{
		ID: hex.EncodeToString(b[:]), AgentID: c.AgentID, Action: c.action(), Resource: c.resource(),
		Requirement: string(e.Requirement), Tier: e.Tier, Reason: e.Reason, ArgumentsHash: hash, CreatedAt: now,
		OpenedBy: c.OpenedBy, RequiredApprovals: required,
	}
	if a.ttl > 0 {
		req.ExpiresAt = now.Add(a.ttl)
	}
	if err := a.store.OpenToolApproval(ctx, req); err != nil {
		return "", fmt.Errorf("toolguard: open approval: %w", err)
	}
	a.record(ctx, AuditApprovalRequest, req, "", "")
	a.emit(EventApprovalPending, req, "")
	return req.ID, nil
}

// Consume implements Approvals. The store decides the winner atomically, so
// concurrent callers across nodes get true at most once.
func (a *StorageApprovals) Consume(ctx context.Context, id string, c Call) (bool, error) {
	code, err := a.Spend(ctx, id, c)
	return code == policy.CodeApprovalConsumed, err
}

// Errors returned by Decide.
var (
	ErrApprovalNotFound   = errors.New("toolguard: approval not found")
	ErrApprovalNotPending = errors.New("toolguard: approval is not pending")
	ErrApprovalExpired    = errors.New("toolguard: approval has expired")
	ErrDecidedByRequired  = errors.New("toolguard: decidedBy is required")
	ErrDecisionInvalid    = errors.New("toolguard: decision must be approve or deny")
	// ErrRequesterCannotApprove means the approver opened the request (or is the agent), which a
	// quorum request never allows.
	ErrRequesterCannotApprove = errors.New("toolguard: the requester cannot approve a request that needs a quorum")
	// ErrDuplicateApprover means this approver already approved the request.
	ErrDuplicateApprover = errors.New("toolguard: this approver already approved the request")
	// ErrStoreUnsupported means the store lacks theauth.ToolApprovalAdminStorage.
	ErrStoreUnsupported = errors.New("toolguard: store does not implement ToolApprovalAdminStorage")
)

// Decision values for DecideInput.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// DecideInput is the human decision on a pending request. DecidedBy is required so every
// decision is attributable.
type DecideInput struct {
	Decision  string
	DecidedBy string
}

// Decide approves or denies a pending request and returns it as stored. It returns
// ErrApprovalNotFound for an unknown id, ErrApprovalExpired for a request past its expiry (which
// is marked expired, audited and announced once) and ErrApprovalNotPending for a request that is
// already approved, denied, spent or expired. Two concurrent decisions on one request produce
// exactly one success.
func (a *StorageApprovals) Decide(ctx context.Context, id string, in DecideInput) (theauth.ToolApproval, error) {
	if in.Decision != DecisionApprove && in.Decision != DecisionDeny {
		return theauth.ToolApproval{}, ErrDecisionInvalid
	}
	if in.DecidedBy == "" {
		return theauth.ToolApproval{}, ErrDecidedByRequired
	}
	admin, ok := a.store.(theauth.ToolApprovalAdminStorage)
	if !ok {
		return theauth.ToolApproval{}, ErrStoreUnsupported
	}
	cur, found, err := admin.GetToolApproval(ctx, id)
	if err != nil {
		return cur, fmt.Errorf("toolguard: load approval %s: %w", id, err)
	}
	if !found {
		return cur, ErrApprovalNotFound
	}
	now := a.now().UTC()
	if err := a.undecided(ctx, cur, now); err != nil {
		return cur, err
	}
	if in.Decision == DecisionApprove && cur.RequiredApprovals > 1 {
		return a.voteQuorum(ctx, admin, cur, in.DecidedBy, now)
	}
	var won bool
	if in.Decision == DecisionApprove {
		won, err = admin.ApproveToolApproval(ctx, id, in.DecidedBy, now)
	} else {
		won, err = admin.DenyToolApproval(ctx, id, in.DecidedBy, now)
	}
	if err != nil {
		return cur, fmt.Errorf("toolguard: decide approval %s: %w", id, err)
	}
	fresh, _, _ := admin.GetToolApproval(ctx, id)
	if !won {
		// Lost a race or the clock moved past the expiry between the read and the write.
		if err := a.undecided(ctx, fresh, a.now().UTC()); err != nil {
			return fresh, err
		}
		return fresh, ErrApprovalNotPending
	}
	if in.Decision == DecisionApprove {
		a.record(ctx, AuditApprovalApproved, fresh, in.DecidedBy, in.DecidedBy)
		a.emit(EventApprovalApproved, fresh, in.DecidedBy)
	} else {
		a.record(ctx, AuditApprovalDenied, fresh, in.DecidedBy, in.DecidedBy)
		a.emit(EventApprovalDenied, fresh, in.DecidedBy)
	}
	return fresh, nil
}

// undecided returns nil when cur can still be decided, ErrApprovalExpired when it is overdue
// (after marking it expired) and ErrApprovalNotPending for any other settled state.
func (a *StorageApprovals) undecided(ctx context.Context, cur theauth.ToolApproval, now time.Time) error {
	switch {
	case !cur.ApprovedAt.IsZero() || !cur.DeniedAt.IsZero() || !cur.ConsumedAt.IsZero():
		return ErrApprovalNotPending
	case !cur.ExpiredAt.IsZero():
		return ErrApprovalExpired
	case !cur.ExpiresAt.IsZero() && !cur.ExpiresAt.After(now):
		a.markExpired(ctx, cur, now)
		return ErrApprovalExpired
	}
	return nil
}

// Approve approves a pending request as approver. It is Decide with DecisionApprove.
func (a *StorageApprovals) Approve(ctx context.Context, id, approver string) error {
	_, err := a.Decide(ctx, id, DecideInput{Decision: DecisionApprove, DecidedBy: approver})
	return err
}

// Deny denies a pending request as denier. It is Decide with DecisionDeny.
func (a *StorageApprovals) Deny(ctx context.Context, id, denier string) error {
	_, err := a.Decide(ctx, id, DecideInput{Decision: DecisionDeny, DecidedBy: denier})
	return err
}

// markExpired flips an overdue request to expired. Only the caller that wins the conditional
// write writes the audit row and sends the event, so an expiry is announced once.
func (a *StorageApprovals) markExpired(ctx context.Context, ap theauth.ToolApproval, now time.Time) bool {
	ex, ok := a.store.(theauth.ToolApprovalExpiryStorage)
	if !ok {
		return false
	}
	won, err := ex.ExpireToolApproval(ctx, ap.ID, now)
	if err != nil || !won {
		return false
	}
	ap.ExpiredAt = now
	a.record(ctx, AuditApprovalExpired, ap, "", "")
	a.emit(EventApprovalExpired, ap, "")
	return true
}

// Cleanup marks every overdue undecided request expired, up to 1000 per call, and returns how
// many it marked. Run it on a timer if you want expiries audited without waiting for a spend or
// a decision to notice them.
func (a *StorageApprovals) Cleanup(ctx context.Context) (int, error) {
	ex, ok := a.store.(theauth.ToolApprovalExpiryStorage)
	if !ok {
		return 0, ErrStoreUnsupported
	}
	now := a.now().UTC()
	marked := 0
	for range 10 {
		batch, err := ex.ListOverdueToolApprovals(ctx, now, 100)
		if err != nil {
			return marked, fmt.Errorf("toolguard: list overdue approvals: %w", err)
		}
		for _, ap := range batch {
			if a.markExpired(ctx, ap, now) {
				marked++
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return marked, nil
}

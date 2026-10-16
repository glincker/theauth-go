// Package toolguard puts the policy engine in front of an agent tool call. It
// has no framework dependency: a tool is any func(ctx, args) (result, error).
//
// A call is allowed, denied, or escalated. An escalated call returns an
// *ApprovalRequiredError carrying an approval id. After a human approves that
// id, the retry passes it with WithApprovalID and the guard spends it once.
package toolguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/glincker/theauth-go/v2/policy"
)

// Errors returned by the guard. Use errors.Is and errors.As to branch.
var (
	// ErrDenied wraps every denial. The tool did not run.
	ErrDenied = errors.New("toolguard: tool call denied")
	// ErrApprovalRequired is matched by *ApprovalRequiredError.
	ErrApprovalRequired = errors.New("toolguard: approval required")
	// ErrGuardFailed wraps a failure of the check itself. The tool did not run.
	ErrGuardFailed = errors.New("toolguard: check failed")
)

// ApprovalRequiredError is returned when a call needs a human or a step up.
type ApprovalRequiredError struct {
	Tool        string
	AgentID     string
	Reason      string
	Tier        string
	Requirement policy.Requirement
	// ApprovalID is set when the guard opened an approval request.
	ApprovalID string
}

// Error implements error.
func (e *ApprovalRequiredError) Error() string {
	return fmt.Sprintf("toolguard: %s requires %s for agent %s: %s", e.Tool, e.Requirement, e.AgentID, e.Reason)
}

// Is makes errors.Is(err, ErrApprovalRequired) true.
func (e *ApprovalRequiredError) Is(target error) bool { return target == ErrApprovalRequired }

// DeniedError carries the reason a call was denied.
type DeniedError struct {
	Tool    string
	AgentID string
	Reason  string
}

// Error implements error.
func (e *DeniedError) Error() string {
	return fmt.Sprintf("toolguard: %s denied for agent %s: %s", e.Tool, e.AgentID, e.Reason)
}

// Is makes errors.Is(err, ErrDenied) true.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// Call describes one tool invocation to authorize.
type Call struct {
	AgentID string
	Tool    string
	// Action defaults to "execute". Resource defaults to "tool:<Tool>".
	Action   string
	Resource string
	// Risk attributes feed the evaluator's risk tiers.
	Amount       float64
	Currency     string
	DataClass    string
	Irreversible bool
	Attributes   map[string]string
}

func (c Call) action() string {
	if c.Action == "" {
		return "execute"
	}
	return c.Action
}

func (c Call) resource() string {
	if c.Resource == "" {
		return "tool:" + c.Tool
	}
	return c.Resource
}

// Approvals stores approval requests and spends them once.
type Approvals interface {
	// Open records a pending request for the call and returns its id.
	Open(ctx context.Context, c Call, e policy.Escalation) (string, error)
	// Consume spends id if it is approved and was opened for the same agent,
	// action and resource. It reports false for an unknown, pending, already
	// spent or mismatched id. A given id returns true at most once.
	Consume(ctx context.Context, id string, c Call) (bool, error)
}

// PoliciesFunc returns the policies that apply to an agent.
type PoliciesFunc func(ctx context.Context, agentID string) ([]*policy.Policy, error)

// Guard authorizes tool calls. Policies is required. Approvals is optional:
// without it an escalation is reported with no approval id and an approval id
// on the context is never honored.
type Guard struct {
	Evaluator policy.Evaluator
	Policies  PoliciesFunc
	Approvals Approvals
	// OnDecision, when set, sees every decision. It cannot change the outcome.
	OnDecision func(Call, policy.Decision)
}

type approvalKey struct{}

// WithApprovalID returns a context carrying the id of an approved request to
// spend on the next guarded call. Pass it only for the call that was approved.
func WithApprovalID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, approvalKey{}, id)
}

func approvalID(ctx context.Context) string {
	id, _ := ctx.Value(approvalKey{}).(string)
	return id
}

// Authorize returns nil when the call may run. Otherwise it returns a
// *DeniedError, an *ApprovalRequiredError, or an error wrapping ErrGuardFailed.
func (g *Guard) Authorize(ctx context.Context, c Call) error {
	if g == nil || g.Policies == nil {
		return fmt.Errorf("%w: no policy source configured", ErrGuardFailed)
	}
	if c.AgentID == "" {
		return fmt.Errorf("%w: no agent id for tool %q", ErrGuardFailed, c.Tool)
	}
	pols, err := g.Policies(ctx, c.AgentID)
	if err != nil {
		return fmt.Errorf("%w: load policies for agent %s: %w", ErrGuardFailed, c.AgentID, err)
	}
	attrs := make(map[string]string, len(c.Attributes)+2)
	for k, v := range c.Attributes {
		attrs[k] = v
	}
	attrs["agent_id"] = c.AgentID
	attrs["tool"] = c.Tool
	d := g.Evaluator.Evaluate(policy.Request{
		Action:       c.action(),
		Resource:     c.resource(),
		Attributes:   attrs,
		Amount:       c.Amount,
		Currency:     c.Currency,
		DataClass:    c.DataClass,
		Irreversible: c.Irreversible,
	}, pols...)
	if g.OnDecision != nil {
		g.OnDecision(c, d)
	}
	switch d.Effect {
	case policy.Allow:
		return nil
	case policy.Escalate:
		return g.escalate(ctx, c, d)
	}
	return &DeniedError{Tool: c.Tool, AgentID: c.AgentID, Reason: d.Reason}
}

func (g *Guard) escalate(ctx context.Context, c Call, d policy.Decision) error {
	esc := policy.Escalation{Requirement: policy.RequireApproval, Reason: d.Reason}
	if d.Escalation != nil {
		esc = *d.Escalation
	}
	e := &ApprovalRequiredError{
		Tool: c.Tool, AgentID: c.AgentID, Reason: d.Reason,
		Tier: esc.Tier, Requirement: esc.Requirement,
	}
	if g.Approvals == nil {
		return e
	}
	// An approval spends only against a human approval requirement. A step up
	// needs a fresh authentication, which an approval id cannot stand in for.
	if id := approvalID(ctx); id != "" && esc.Requirement == policy.RequireApproval {
		ok, err := g.Approvals.Consume(ctx, id, c)
		if err != nil {
			return fmt.Errorf("%w: spend approval %s: %w", ErrGuardFailed, id, err)
		}
		if ok {
			return nil
		}
	}
	id, err := g.Approvals.Open(ctx, c, esc)
	if err != nil {
		return fmt.Errorf("%w: open approval: %w", ErrGuardFailed, err)
	}
	e.ApprovalID = id
	return e
}

// Tool wraps fn so it runs only when the guard allows the call. build maps the
// arguments to the Call (the agent id usually comes from ctx or args). On any
// error from the guard, fn is not called and the zero R is returned.
func Tool[A, R any](g *Guard, build func(ctx context.Context, args A) Call, fn func(ctx context.Context, args A) (R, error)) func(ctx context.Context, args A) (R, error) {
	return func(ctx context.Context, args A) (R, error) {
		var zero R
		if err := g.Authorize(ctx, build(ctx, args)); err != nil {
			return zero, err
		}
		return fn(ctx, args)
	}
}

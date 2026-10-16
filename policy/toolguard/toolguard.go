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

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/policy"
)

// Errors returned by the guard. Use errors.Is and errors.As to branch.
var (
	// ErrDenied wraps every denial. The tool did not run.
	ErrDenied = errors.New("toolguard: tool call denied")
	// ErrApprovalRequired is matched by *ApprovalRequiredError.
	ErrApprovalRequired = errors.New("toolguard: approval required")
	// ErrTaintViolation is matched by *TaintViolationError, a call a taint rule
	// with effect deny refused. It also matches ErrDenied.
	ErrTaintViolation = errors.New("toolguard: taint violation")
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

// TaintViolationError is returned when a taint rule with effect deny refuses a
// call. It is distinct from a plain policy deny: errors.Is matches both
// ErrTaintViolation and ErrDenied.
type TaintViolationError struct {
	Tool    string
	AgentID string
	Reason  string
	// Verdict holds the violated checks and the labels they were computed from.
	Verdict *policy.TaintVerdict
}

// Error implements error.
func (e *TaintViolationError) Error() string {
	return fmt.Sprintf("toolguard: %s refused for agent %s: %s", e.Tool, e.AgentID, e.Reason)
}

// Is makes errors.Is match ErrTaintViolation and ErrDenied.
func (e *TaintViolationError) Is(target error) bool {
	return target == ErrTaintViolation || target == ErrDenied
}

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
	// Provenance labels the arguments, keyed by argument name. The key "*"
	// (CallLabelsKey) labels the whole call. Nil means unlabeled, and the call
	// is evaluated as before.
	Provenance map[string][]string
	// Args are the call arguments (a struct or a map with string keys). When
	// the Guard has a Tracker, labels of tracked strings inside Args are merged
	// into Provenance. Tool sets it from the typed arguments when empty.
	Args any
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
	// Tracker, when set, adds labels of tracked strings found in Call.Args and
	// registers each successful Tool result as tool_output:<tool>.
	Tracker *ProvenanceTracker
	// Audit, when set, receives one decision record for every call that has
	// provenance labels, with the labels and the taint verdict as the record's
	// input provenance. A call without labels emits nothing. The method value
	// (*theauth.TheAuth).EmitAudit fits.
	Audit func(ctx context.Context, action string, target theauth.TargetRef, metadata map[string]any)
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
	_, err := g.authorize(ctx, c)
	return err
}

// authorize returns the resolved provenance along with the outcome.
func (g *Guard) authorize(ctx context.Context, c Call) (map[string][]string, error) {
	prov, d, err := g.decide(ctx, c)
	g.audit(ctx, c, prov, d, err)
	return prov, err
}

func (g *Guard) decide(ctx context.Context, c Call) (map[string][]string, *policy.Decision, error) {
	if g == nil || g.Policies == nil {
		return nil, nil, fmt.Errorf("%w: no policy source configured", ErrGuardFailed)
	}
	if c.AgentID == "" {
		return nil, nil, fmt.Errorf("%w: no agent id for tool %q", ErrGuardFailed, c.Tool)
	}
	pols, err := g.Policies(ctx, c.AgentID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: load policies for agent %s: %w", ErrGuardFailed, c.AgentID, err)
	}
	attrs := make(map[string]string, len(c.Attributes)+2)
	for k, v := range c.Attributes {
		attrs[k] = v
	}
	attrs["agent_id"] = c.AgentID
	attrs["tool"] = c.Tool
	var tracked map[string][]string
	if g.Tracker != nil && c.Args != nil {
		tracked = g.Tracker.ArgLabels(c.Args)
	}
	prov := MergeProvenance(c.Provenance, tracked)
	d := g.Evaluator.Evaluate(policy.Request{
		Action:       c.action(),
		Resource:     c.resource(),
		Attributes:   attrs,
		Amount:       c.Amount,
		Currency:     c.Currency,
		DataClass:    c.DataClass,
		Irreversible: c.Irreversible,
		Provenance:   prov,
	}, pols...)
	if g.OnDecision != nil {
		g.OnDecision(c, d)
	}
	switch d.Effect {
	case policy.Allow:
		return prov, &d, nil
	case policy.Escalate:
		return prov, &d, g.escalate(ctx, c, d)
	}
	if d.Taint != nil && d.Taint.Verdict == policy.TaintDeny {
		return prov, &d, &TaintViolationError{Tool: c.Tool, AgentID: c.AgentID, Reason: d.Reason, Verdict: d.Taint}
	}
	return prov, &d, &DeniedError{Tool: c.Tool, AgentID: c.AgentID, Reason: d.Reason}
}

// audit records one decision when the call carried provenance labels.
func (g *Guard) audit(ctx context.Context, c Call, prov map[string][]string, d *policy.Decision, err error) {
	if g.Audit == nil || d == nil || len(prov) == 0 {
		return
	}
	outcome := "allowed"
	var approval *ApprovalRequiredError
	var taint *TaintViolationError
	switch {
	case errors.As(err, &taint):
		outcome = "taint_denied"
	case errors.Is(err, ErrDenied):
		outcome = "denied"
	case errors.As(err, &approval):
		outcome = "approval_required"
	case err != nil:
		outcome = "failed"
	case d.Effect == policy.Escalate:
		outcome = "approved"
	}
	record := map[string]any{"labels": provenanceRecord(prov)}
	if d.Taint != nil {
		record["taint"] = map[string]any{
			"verdict": d.Taint.Verdict,
			"matches": matchesRecord(d.Taint.Matches),
		}
	}
	md, _ := audit.MetadataFromContext(ctx)
	md.ActorID = c.AgentID
	md.InputProvenance = record
	g.Audit(audit.WithAuditMetadata(ctx, md), "agent.authorize",
		theauth.TargetRef{Type: "tool", ID: c.Tool},
		map[string]any{
			"agent_id": c.AgentID, "tool": c.Tool, "action": c.action(), "resource": c.resource(),
			"effect": string(d.Effect), "outcome": outcome, "reason": d.Reason,
		})
}

func provenanceRecord(prov map[string][]string) map[string]any {
	out := make(map[string]any, len(prov))
	for k, ls := range prov {
		items := make([]any, len(ls))
		for i, l := range ls {
			items[i] = l
		}
		out[k] = items
	}
	return out
}

func matchesRecord(ms []policy.TaintMatch) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		labels := make([]any, len(m.Labels))
		for j, l := range m.Labels {
			labels[j] = l
		}
		out[i] = map[string]any{"rule": m.Rule, "kind": m.Kind, "arg": m.Arg, "labels": labels, "effect": string(m.Effect)}
	}
	return out
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
		c := build(ctx, args)
		if c.Args == nil && g != nil && g.Tracker != nil {
			c.Args = args
		}
		prov, err := g.authorize(ctx, c)
		if err != nil {
			return zero, err
		}
		res, err := fn(ctx, args)
		if err == nil && g.Tracker != nil {
			g.Tracker.TrackResult(c.Tool, res, DeriveLabels(prov)...)
		}
		return res, err
	}
}

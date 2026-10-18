// Package hook runs before authorize hooks: code that sees an agent call after
// the agent is resolved and may deny it, send it to approval, or let it
// continue to the normal policy checks. A hook can live in process (Func) or
// at a vendor endpoint reached over HTTPS (HTTPGuard, protocol 2026-10, wire
// compatible with the TypeScript library's httpGuard).
//
// A Runner applies the safety rules: a per hook timeout (default 2s), panic
// recovery, and deny on timeout, error, panic or malformed verdict. An allow
// from a hook never overrides theauth's own permission checks; it only means
// the hook did not object.
//
// The package depends on the standard library only (plus the module's SSRF
// safe dialer), so the root theauth package and policy/toolguard can both use
// it without an import cycle.
package hook

import (
	"context"
	"errors"
	"time"
)

// Decision is a hook verdict: allow, deny or escalate.
type Decision string

// Verdicts a hook may return.
const (
	// Allow means the hook does not object. Normal policy still applies.
	Allow Decision = "allow"
	// Deny refuses the call.
	Deny Decision = "deny"
	// Escalate sends the call to the approval flow.
	Escalate Decision = "escalate"
)

// Code is the decision code a hook outcome reports. The values equal the
// policy package's DecisionCode constants of the same name (a test in
// policy/toolguard enforces it); this package cannot import policy because
// policy imports the root package, which imports this one.
type Code string

// Codes reported on a blocked outcome.
const (
	// CodeHookDenied means a hook returned deny.
	CodeHookDenied Code = "hook_denied"
	// CodeHookTimeout means a hook did not answer within its timeout.
	CodeHookTimeout Code = "hook_timeout"
	// CodeHookError means a hook failed: an error, a panic, a malformed
	// verdict, or a guard response that did not verify.
	CodeHookError Code = "hook_error"
	// CodeApprovalRequired means a hook returned escalate.
	CodeApprovalRequired Code = "approval_required"
)

// Sources say which entry point asked. The values match the TypeScript
// AuthorizeSource strings that vendors already accept.
const (
	SourceAuthorize        = "authorize"
	SourceAuthorizeByToken = "authorizeByToken"
	SourcePolicyEvaluate   = "policy.evaluate"
	SourceExplain          = "explain"
)

const (
	defaultAgentType      = "autonomous"
	maxClip               = 256
	maxMetadataKeys       = 16
	defaultDenyReason     = "Blocked by beforeAuthorize hook"
	defaultEscalateReason = "beforeAuthorize hook requires approval"
)

// Input is what a hook sees. It never carries the agent token or session
// data. The JSON form is the "input" object of the 2026-10 guard protocol.
type Input struct {
	AgentID  string `json:"agentId"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	// Arguments are the call arguments. They may hold user data: an HTTPGuard
	// sends them unless its Redact function drops them.
	Arguments  map[string]any `json:"arguments,omitempty"`
	Agent      AgentInfo      `json:"agent"`
	Delegation Delegation     `json:"delegation"`
	// Source is one of the Source constants.
	Source string `json:"source"`
	// IP is the client IP when known.
	IP string `json:"ip,omitempty"`
	// DryRun is true for a question that must not be counted as a real call.
	DryRun bool `json:"dryRun"`
}

// AgentInfo describes the acting agent.
type AgentInfo struct {
	ID       string `json:"id"`
	OwnerID  string `json:"ownerId"`
	TenantID string `json:"tenantId,omitempty"`
	// Type is autonomous, delegated or service. The Go library has no agent
	// types and reports autonomous.
	Type string `json:"type"`
	Name string `json:"name"`
}

// Delegation is the chain from the accountable human to the acting agent.
type Delegation struct {
	// RootOwnerID is the human or organization that owns the root agent.
	RootOwnerID string `json:"rootOwnerId,omitempty"`
	// Path lists agent ids from the root agent to the acting agent. Length 1
	// when the agent is not delegated.
	Path []string `json:"path"`
	// Links are the grants along Path, root first.
	Links []Link `json:"links"`
	// Inbound are all active grants whose target is the acting agent.
	Inbound []Link `json:"inbound"`
}

// Link is one delegation grant from FromAgent to ToAgent.
type Link struct {
	DelegationID string       `json:"delegationId"`
	FromAgent    string       `json:"fromAgent"`
	ToAgent      string       `json:"toAgent"`
	Permissions  []Permission `json:"permissions"`
	Depth        int          `json:"depth"`
	MaxDepth     int          `json:"maxDepth"`
	// ExpiresAt is nil for a grant without an expiry.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// Permission is one permission carried by a grant.
type Permission struct {
	Resource    string         `json:"resource"`
	Actions     []string       `json:"actions"`
	Constraints map[string]any `json:"constraints,omitempty"`
	Relation    string         `json:"relation,omitempty"`
}

// normalized returns a copy whose slices encode as [] rather than null, as the
// protocol requires.
func (in Input) normalized() Input {
	if in.Agent.Type == "" {
		in.Agent.Type = defaultAgentType
	}
	if in.Agent.ID == "" {
		in.Agent.ID = in.AgentID
	}
	if in.Source == "" {
		in.Source = SourceAuthorize
	}
	d := in.Delegation
	if len(d.Path) == 0 {
		d.Path = []string{in.AgentID}
	}
	d.Links = normalizeLinks(d.Links)
	d.Inbound = normalizeLinks(d.Inbound)
	in.Delegation = d
	return in
}

func normalizeLinks(ls []Link) []Link {
	out := make([]Link, len(ls))
	for i, l := range ls {
		perms := make([]Permission, len(l.Permissions))
		for j, p := range l.Permissions {
			if p.Actions == nil {
				p.Actions = []string{}
			}
			perms[j] = p
		}
		l.Permissions = perms
		out[i] = l
	}
	return out
}

// Verdict is a hook's answer.
type Verdict struct {
	Decision Decision `json:"decision"`
	// Reason is returned to the calling agent, so it must not hold secrets.
	// Required (non-empty) on the wire for deny.
	Reason string `json:"reason,omitempty"`
	// Code is a vendor rule code, deny only. It is reported as RuleID when
	// RuleID is empty.
	Code string `json:"code,omitempty"`
	// Guard names the guard or rule set that decided, for the audit record.
	Guard  string `json:"guard,omitempty"`
	RuleID string `json:"ruleId,omitempty"`
	// Metadata is a small scalar map (string, float64, bool) for the audit
	// record: at most 16 keys, strings clipped to 256 bytes.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Hook decides one call. An error denies the call with hook_error. A hook
// must return promptly once ctx is done: the Runner stops waiting at the
// timeout, and a hook that ignores ctx keeps its goroutine until it returns.
type Hook interface {
	BeforeAuthorize(ctx context.Context, in Input) (Verdict, error)
}

// Func adapts a function to Hook.
type Func func(ctx context.Context, in Input) (Verdict, error)

// BeforeAuthorize calls f.
func (f Func) BeforeAuthorize(ctx context.Context, in Input) (Verdict, error) { return f(ctx, in) }

// ErrMalformedVerdict is reported when a hook returns a verdict whose Decision
// is not allow, deny or escalate.
var ErrMalformedVerdict = errors.New("hook: malformed verdict")

// Compose runs hooks in order with deny overrides: the first deny stops the
// run and wins, otherwise the first escalate beats allow, otherwise allow. An
// error or malformed verdict from any hook stops the run and is returned, so
// the Runner denies. Nil hooks are skipped; Compose() allows.
func Compose(hooks ...Hook) Hook {
	hs := make([]Hook, 0, len(hooks))
	for _, h := range hooks {
		if h != nil {
			hs = append(hs, h)
		}
	}
	return composed(hs)
}

type composed []Hook

func (c composed) BeforeAuthorize(ctx context.Context, in Input) (Verdict, error) {
	var escalation *Verdict
	for _, h := range c {
		if err := ctx.Err(); err != nil {
			return Verdict{}, err
		}
		v, err := h.BeforeAuthorize(ctx, in)
		if err != nil {
			return Verdict{}, err
		}
		switch v.Decision {
		case Deny:
			return v, nil
		case Escalate:
			if escalation == nil {
				vv := v
				escalation = &vv
			}
		case Allow:
		default:
			return Verdict{}, ErrMalformedVerdict
		}
	}
	if escalation != nil {
		return *escalation, nil
	}
	return Verdict{Decision: Allow}, nil
}

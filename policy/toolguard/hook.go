package toolguard

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/hook"
)

// applyHook runs Guard.BeforeAuthorize on a call the policy allowed or
// escalated, and combines the two with deny overrides: a hook deny (or
// timeout, or failure) wins, a hook escalate turns an allow into an
// escalation, and a hook allow leaves the policy decision as it was.
func (g *Guard) applyHook(ctx context.Context, c Call, prov map[string][]string, d policy.Decision, evalErr error) (map[string][]string, *policy.Decision, *hook.Outcome, error) {
	if evalErr != nil {
		return prov, &d, nil, evalErr
	}
	in := hook.Input{AgentID: c.AgentID, Action: c.action(), Resource: c.resource(), Source: hook.SourceAuthorize}
	if md, ok := audit.MetadataFromContext(ctx); ok {
		in.IP = md.IP
	}
	if g.HookSubject != nil {
		info, chain, err := g.HookSubject(ctx, c.AgentID)
		if err != nil {
			return prov, &d, nil, guardFailed(policy.CodePolicyIndeterminate, fmt.Errorf("%w: describe agent %s for the hook: %w", ErrGuardFailed, c.AgentID, err))
		}
		in.Agent, in.Delegation = info, chain
	}
	var out hook.Outcome
	if args, err := argumentsMap(c.Args); err != nil {
		// Arguments that cannot be encoded are never silently dropped: the
		// guard would decide on less than the call carries. Fail closed.
		out = hook.Outcome{Decision: hook.Deny, Code: hook.CodeHookError, Reason: "beforeAuthorize hook failed", Cause: err}
	} else {
		in.Arguments = args
		out = g.BeforeAuthorize.Run(ctx, in)
	}
	switch out.Decision {
	case hook.Allow:
		if d.Effect == policy.Escalate {
			return prov, &d, &out, g.escalate(ctx, c, d)
		}
		return prov, &d, &out, nil
	case hook.Escalate:
		if d.Effect != policy.Escalate {
			d.Effect, d.Allowed, d.Code, d.Reason = policy.Escalate, false, policy.CodeApprovalRequired, out.Reason
			d.Escalation = &policy.Escalation{Requirement: policy.RequireApproval, Reason: out.Reason}
		}
		return prov, &d, &out, g.escalate(ctx, c, d)
	}
	code := policy.DecisionCode(out.Code)
	d.Effect, d.Allowed, d.Code, d.Reason, d.Escalation = policy.Deny, false, code, out.Reason, nil
	return prov, &d, &out, &DeniedError{Tool: c.Tool, AgentID: c.AgentID, Reason: out.Reason, Code: code}
}

// argumentsMap turns Call.Args into the JSON object the hook input carries.
// A non object value is sent as {"value": ...}.
func argumentsMap(args any) (map[string]any, error) {
	switch a := args.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return a, nil
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("toolguard: encode arguments for the hook: %w", err)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil && m != nil {
		return m, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("toolguard: encode arguments for the hook: %w", err)
	}
	return map[string]any{"value": v}, nil
}

package policy

// DecisionCode is the machine-readable outcome of an authorization decision.
// It is set where the decision is made and carried on Decision.Code, on the
// toolguard errors, in audit metadata (key decision_code) and in HTTP denial
// bodies (key decision_code), so callers branch on a closed set instead of
// parsing Reason text. The values match the TypeScript library's
// DECISION_CODES one for one.
type DecisionCode string

// Decision codes. Every constant here must have a row in the decision codes
// table of docs/agent-policies.md (a test enforces it).
const (
	// CodeAllowed means an allow statement matched and nothing narrowed it.
	CodeAllowed DecisionCode = "allowed"
	// CodeApprovalConsumed means an escalated call went through because a
	// human approval was spent. Reported by toolguard (audit and CodeOf
	// semantics); the evaluator itself reports the escalation.
	CodeApprovalConsumed DecisionCode = "approval_consumed"
	// CodeNoPermission means no allow statement matched (default deny), an
	// explicit deny matched, or a permission boundary refused.
	CodeNoPermission DecisionCode = "no_permission"
	// CodeRateLimited means the per agent rate limit refused the call.
	CodeRateLimited DecisionCode = "rate_limited"
	// CodeIPNotAllowed means an allow statement matched the action and
	// resource but its source IP condition failed.
	CodeIPNotAllowed DecisionCode = "ip_not_allowed"
	// CodeTimeRestricted means an allow statement matched the action and
	// resource but its time window condition failed.
	CodeTimeRestricted DecisionCode = "time_restricted"
	// CodeArgumentRejected means a call argument was refused. Reserved: the
	// Go evaluator does not produce it yet.
	CodeArgumentRejected DecisionCode = "argument_rejected"
	// CodeApprovalRequired means a statement escalated the call and no valid
	// approval was presented.
	CodeApprovalRequired DecisionCode = "approval_required"
	// CodeApprovalInvalid means an approval id was presented but could not be
	// spent (unknown, pending, already used or issued for another call).
	CodeApprovalInvalid DecisionCode = "approval_invalid"
	// CodeAgentNotFound means the agent id is unknown.
	CodeAgentNotFound DecisionCode = "agent_not_found"
	// CodeAgentRevoked means the agent was revoked or suspended. Reserved
	// until the agent lifecycle exposes a typed error to classify.
	CodeAgentRevoked DecisionCode = "agent_revoked"
	// CodeAgentExpired means the agent passed its expiry. Reserved.
	CodeAgentExpired DecisionCode = "agent_expired"
	// CodeInvalidToken means the presented token failed verification.
	// Reserved for the token layer; policy never sees an invalid token.
	CodeInvalidToken DecisionCode = "invalid_token"
	// CodeOwnerMismatch means the caller does not own the agent. Reserved.
	CodeOwnerMismatch DecisionCode = "owner_mismatch"
	// CodeHookDenied means a before authorize hook refused the call. Reserved.
	CodeHookDenied DecisionCode = "hook_denied"
	// CodeHookTimeout means a before authorize hook timed out. Reserved.
	CodeHookTimeout DecisionCode = "hook_timeout"
	// CodeHookError means a before authorize hook failed. Reserved.
	CodeHookError DecisionCode = "hook_error"
	// CodeTaintViolation means a taint rule refused or escalated the call.
	CodeTaintViolation DecisionCode = "taint_violation"
	// CodeRiskEscalation means a risk tier turned an allow into an escalation.
	CodeRiskEscalation DecisionCode = "risk_escalation"
	// CodePolicyIndeterminate means no decision could be reached (policies or
	// subjects failed to load, no policy source, no agent id). Fail closed.
	CodePolicyIndeterminate DecisionCode = "policy_indeterminate"
)

// AllDecisionCodes lists every defined code in declaration order.
func AllDecisionCodes() []DecisionCode {
	return []DecisionCode{
		CodeAllowed, CodeApprovalConsumed, CodeNoPermission, CodeRateLimited,
		CodeIPNotAllowed, CodeTimeRestricted, CodeArgumentRejected,
		CodeApprovalRequired, CodeApprovalInvalid, CodeAgentNotFound,
		CodeAgentRevoked, CodeAgentExpired, CodeInvalidToken, CodeOwnerMismatch,
		CodeHookDenied, CodeHookTimeout, CodeHookError, CodeTaintViolation,
		CodeRiskEscalation, CodePolicyIndeterminate,
	}
}

// String returns the wire value.
func (c DecisionCode) String() string { return string(c) }

// Valid reports whether c is one of the defined codes.
func (c DecisionCode) Valid() bool {
	for _, k := range AllDecisionCodes() {
		if c == k {
			return true
		}
	}
	return false
}

// Permits reports whether the code means the call went through.
func (c DecisionCode) Permits() bool { return c == CodeAllowed || c == CodeApprovalConsumed }

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
	// CodeApprovalInvalid is the generic fallback for an approval id that
	// could not be spent. The built in toolguard approvals report one of the
	// specific approval_* codes below instead; only a custom Approvals that
	// cannot say why still reports this one.
	CodeApprovalInvalid DecisionCode = "approval_invalid"
	// CodeApprovalNotFound means the presented approval id is unknown.
	CodeApprovalNotFound DecisionCode = "approval_not_found"
	// CodeApprovalPending means the request is still waiting for a human.
	CodeApprovalPending DecisionCode = "approval_pending"
	// CodeApprovalDenied means a human denied the request.
	CodeApprovalDenied DecisionCode = "approval_denied"
	// CodeApprovalExpired means the request passed its expiry before it was
	// decided or spent.
	CodeApprovalExpired DecisionCode = "approval_expired"
	// CodeApprovalAlreadyUsed means the approval was already spent.
	CodeApprovalAlreadyUsed DecisionCode = "approval_already_used"
	// CodeApprovalMismatch means the approval was issued for another agent,
	// action or resource.
	CodeApprovalMismatch DecisionCode = "approval_mismatch"
	// CodeApprovalArgumentsMismatch means the arguments presented at spend
	// time differ from the ones the human approved.
	CodeApprovalArgumentsMismatch DecisionCode = "approval_arguments_mismatch"
	// CodeApprovalStepUpInsufficient means the approval was granted under a
	// weaker step-up rule than the policy demands now. Reserved here: the Go
	// approvals do not record a step-up rule yet.
	CodeApprovalStepUpInsufficient DecisionCode = "approval_step_up_insufficient"
	// CodeApprovalGranted is the code of the decision event emitted when a
	// human approves a request. It is not a spend: the spend reports
	// approval_consumed.
	CodeApprovalGranted DecisionCode = "approval_granted"
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
	// CodeConfirmationRequired means the token is sender constrained (DPoP or
	// mTLS, RFC 7800) and the request carried no proof of the key. Reserved
	// until the resource server side checks land.
	CodeConfirmationRequired DecisionCode = "confirmation_required"
	// CodeConfirmationFailed means the proof of possession does not match the
	// key or certificate the token is bound to. Reserved, see above.
	CodeConfirmationFailed DecisionCode = "confirmation_failed"
	// CodeDeviceNotFound means the device id is unknown (IoT devices).
	CodeDeviceNotFound DecisionCode = "device_not_found"
	// CodeDeviceSuspended means the device is suspended. Reversible.
	CodeDeviceSuspended DecisionCode = "device_suspended"
	// CodeDeviceRevoked means the device was revoked.
	CodeDeviceRevoked DecisionCode = "device_revoked"
	// CodeDeviceExpired means the device passed its expiry.
	CodeDeviceExpired DecisionCode = "device_expired"
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
		CodeApprovalRequired, CodeApprovalInvalid, CodeApprovalNotFound,
		CodeApprovalPending, CodeApprovalDenied, CodeApprovalExpired,
		CodeApprovalAlreadyUsed, CodeApprovalMismatch, CodeApprovalArgumentsMismatch,
		CodeApprovalStepUpInsufficient, CodeApprovalGranted, CodeAgentNotFound,
		CodeAgentRevoked, CodeAgentExpired, CodeInvalidToken,
		CodeConfirmationRequired, CodeConfirmationFailed,
		CodeDeviceNotFound, CodeDeviceSuspended, CodeDeviceRevoked, CodeDeviceExpired, CodeOwnerMismatch,
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

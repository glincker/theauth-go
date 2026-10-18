package audit

import (
	"fmt"
	"sort"
)

// Shared audit event names. The strings are identical to the TypeScript SDK
// (packages/core/src/audit/events.ts and AuditEvent in types.ts) wherever the
// concept exists, so a consumer can filter both stores with one vocabulary.
// An event says what happened; the action column keeps the domain verb and is
// the only thing hashed into the chain. Event is never hashed.
const (
	EventAuthorize        = "authorize"
	EventAuthorizeToken   = "authorize.token"
	EventPolicyEvaluate   = "policy.evaluate"
	EventMCPToolCall      = "mcp.tool.call" // reserved: no Go writer yet (mcpresource)
	EventDelegationCreate = "delegation.create"
	EventDelegationRevoke = "delegation.revoke"
	EventAgentCreate      = "agent.create"
	EventAgentRevoke      = "agent.revoke"
	EventAgentCascade     = "agent.cascade.revoked"
	EventApprovalRequest  = "approval.request"
	EventApprovalApprove  = "approval.approve"
	EventApprovalDeny     = "approval.deny"
	EventVaultRead        = "vault.read"
	EventAuditCheckpoint  = "audit.checkpoint" // reserved: no Go writer yet
	EventAuditWriteFailed = "audit.write_failed"
	EventAuditErasure     = "audit.erasure" // reserved: no Go writer yet
)

// events is the closed set accepted by ValidEvent. Go specific names are
// added here with a comment saying why the TypeScript SDK has no equivalent.
// There are none today: every Go writer either maps to a shared name or keeps
// a NULL event, which the design prefers over inventing names that only one
// SDK understands.
var events = map[string]struct{}{
	EventAuthorize: {}, EventAuthorizeToken: {}, EventPolicyEvaluate: {}, EventMCPToolCall: {},
	EventDelegationCreate: {}, EventDelegationRevoke: {}, EventAgentCreate: {}, EventAgentRevoke: {},
	EventAgentCascade: {}, EventApprovalRequest: {}, EventApprovalApprove: {}, EventApprovalDeny: {},
	EventVaultRead: {}, EventAuditCheckpoint: {}, EventAuditWriteFailed: {}, EventAuditErasure: {},
}

// Events returns the closed event vocabulary, sorted.
func Events() []string {
	out := make([]string, 0, len(events))
	for e := range events {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ValidEvent reports whether e is a name in the closed vocabulary. The empty
// string (no event, stored as NULL) is not a name and reports false.
func ValidEvent(e string) bool {
	_, ok := events[e]
	return ok
}

// ValidateEvent returns nil for the empty string (no event) and for every name
// in the vocabulary, and an error naming the value otherwise. Writers call it
// before setting AuditEvent.Event so a typo cannot create a value no filter finds.
func ValidateEvent(e string) error {
	if e == "" || ValidEvent(e) {
		return nil
	}
	return fmt.Errorf("theauth: unknown audit event %q", e)
}

// actionEvents maps the action strings Go writers use today to shared events.
// The migrations backfill (postgres 0032, mysql 0031, sqlite 0036) uses this
// same table in SQL CASE form; keep them in step.
//
//	action                      event
//	agent.authorize             authorize
//	agent.authorize_denied      authorize
//	agent.token_minted          authorize.token
//	agent.token_denied          authorize.token
//	policy.decision             policy.evaluate
//	delegation.granted          delegation.create
//	delegation.revoked          delegation.revoke
//	agent.created               agent.create
//	agent.revoked               agent.revoke
//	agent.cascade.revoked       agent.cascade.revoked
//	approval.request            approval.request
//	tool_approval.approved      approval.approve
//	tool_approval.denied        approval.deny
//	vault.token.issued          vault.read
//	audit.events_dropped        audit.write_failed
//
// Deliberately NULL (empty): agent.suspended and agent.resumed (not a revoke),
// approval.decided (the writer picks approve or deny from the decision going
// forward, a backfill cannot), policy.denied in internal/cimd (client policy,
// not agent policy), and every other vault.* action. Unknown actions map to
// the empty string and are never guessed.
var actionEvents = map[string]string{
	"agent.authorize":        EventAuthorize,
	"agent.authorize_denied": EventAuthorize,
	"agent.token_minted":     EventAuthorizeToken,
	"agent.token_denied":     EventAuthorizeToken,
	"policy.decision":        EventPolicyEvaluate,
	"delegation.granted":     EventDelegationCreate,
	"delegation.revoked":     EventDelegationRevoke,
	"agent.created":          EventAgentCreate,
	"agent.revoked":          EventAgentRevoke,
	"agent.cascade.revoked":  EventAgentCascade,
	"approval.request":       EventApprovalRequest,
	"tool_approval.approved": EventApprovalApprove,
	"tool_approval.denied":   EventApprovalDeny,
	"vault.token.issued":     EventVaultRead,
	"audit.events_dropped":   EventAuditWriteFailed,
}

// EventForAction returns the shared event for an existing Go action string, or
// "" when the action has none. Writers use it when they do not pass an event
// themselves, and the backfill uses the same table.
func EventForAction(action string) string {
	return actionEvents[action]
}

// ActionEvents returns a copy of the action to event table.
func ActionEvents() map[string]string {
	out := make(map[string]string, len(actionEvents))
	for k, v := range actionEvents {
		out[k] = v
	}
	return out
}

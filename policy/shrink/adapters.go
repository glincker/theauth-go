package shrink

import (
	"context"
	"fmt"
	"time"

	oklog "github.com/oklog/ulid/v2"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/policy"
)

// DecisionAction is the audit event action the adapters read and write for
// one authorization decision of an agent.
const DecisionAction = "agent.authorize"

// Metadata keys of a decision event. The authorized action and resource live
// in metadata because the event's own Action names the event type.
const (
	MetaAction   = "action"
	MetaResource = "resource"
	MetaResult   = "result"
	MetaReason   = "reason"
)

// DecisionEvent builds the audit event that AuditRows reads back. Emit it from
// toolguard.Guard.OnDecision, or from any code that records agent decisions.
// result is one of the Result constants; use ResultOf to map a policy.Decision.
func DecisionEvent(id theauth.ULID, agentID, action, resource, result, reason string, at time.Time, chain []string) theauth.AuditEvent {
	return theauth.AuditEvent{
		ID:              id,
		Action:          DecisionAction,
		TargetType:      "resource",
		TargetID:        resource,
		ActorID:         agentID,
		DelegationChain: chain,
		CreatedAt:       at,
		Metadata: map[string]any{
			MetaAction:   action,
			MetaResource: resource,
			MetaResult:   result,
			MetaReason:   reason,
		},
	}
}

// ResultOf maps a policy decision to a row result.
func ResultOf(d policy.Decision) string {
	switch d.Effect {
	case policy.Allow:
		return ResultAllowed
	case policy.Escalate:
		return ResultEscalated
	}
	return ResultDenied
}

// AuditReader is the read half of theauth.AuditStorage.
type AuditReader interface {
	QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) (events []theauth.AuditEvent, nextCursor string, err error)
}

// AuditRows adapts an audit store to RowSource. It reads DecisionAction events
// whose ActorID is the agent. The store pages newest first with its own cursor
// and has no actor filter, so rows are filtered after each read and a page can
// be short; memory is still bounded by the page size.
type AuditRows struct {
	Store AuditReader
}

// Rows implements RowSource.
func (a AuditRows) Rows(ctx context.Context, q RowQuery) ([]DecisionRow, string, error) {
	aq := theauth.AuditQuery{Action: DecisionAction, After: q.After, Limit: min(pageSize(q.Limit), 200)}
	if !q.Since.IsZero() {
		t := q.Since
		aq.Since = &t
	}
	if !q.Until.IsZero() {
		t := q.Until
		aq.Until = &t
	}
	events, next, err := a.Store.QueryAuditEvents(ctx, aq)
	if err != nil {
		return nil, "", fmt.Errorf("query audit events: %w", err)
	}
	rows := make([]DecisionRow, 0, len(events))
	for _, e := range events {
		if e.ActorID != q.AgentID {
			continue
		}
		rows = append(rows, rowFromEvent(e))
	}
	return rows, next, nil
}

func rowFromEvent(e theauth.AuditEvent) DecisionRow {
	str := func(k string) string {
		s, _ := e.Metadata[k].(string)
		return s
	}
	resource := str(MetaResource)
	if resource == "" {
		resource = e.TargetID
	}
	return DecisionRow{
		ID:              e.ID.String(),
		Action:          str(MetaAction),
		Resource:        resource,
		Result:          str(MetaResult),
		Reason:          str(MetaReason),
		Timestamp:       e.CreatedAt,
		DelegationChain: e.DelegationChain,
	}
}

// PolicyLoader returns the policies that apply to an agent. It has the same
// shape as toolguard.PoliciesFunc, so the function a guard uses can be reused.
type PolicyLoader func(ctx context.Context, agentID string) ([]*policy.Policy, error)

// DelegationReader is the read half of theauth.Storage for delegation grants.
type DelegationReader interface {
	DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error)
}

// StorageGrants adapts a policy loader and the delegation store to
// GrantSource. Policies supplies the own grants; either field may be nil.
// Delegation grants are active (not revoked) and unexpired at now; each scope
// becomes one grant on the delegated resource, with the grant id as ChainID.
type StorageGrants struct {
	Policies    PolicyLoader
	Delegations DelegationReader
}

// Grants implements GrantSource.
func (s StorageGrants) Grants(ctx context.Context, agentID string, now time.Time) ([]Grant, error) {
	var out []Grant
	seen := map[string]struct{}{}
	add := func(g Grant) {
		k := atomKey(g.Permission)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, g)
	}
	if s.Policies != nil {
		pols, err := s.Policies(ctx, agentID)
		if err != nil {
			return nil, fmt.Errorf("load policies for agent %s: %w", agentID, err)
		}
		for _, g := range PolicyGrants(pols) {
			add(g)
		}
	}
	if s.Delegations != nil {
		id, err := oklog.ParseStrict(agentID)
		if err != nil {
			return nil, fmt.Errorf("parse agent id %q: %w", agentID, err)
		}
		grants, err := s.Delegations.DelegationGrantsByAgentID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("load delegation grants for agent %s: %w", agentID, err)
		}
		for _, g := range DelegationGrants(grants, now) {
			add(g)
		}
	}
	return out, nil
}

// PolicyGrants splits the allow statements of pols into single-action grants,
// in document order. Deny and escalate statements are not grants and are left
// out; they stay in force when you apply a suggestion, because a suggestion
// only rewrites allow statements. Duplicates are dropped.
func PolicyGrants(pols []*policy.Policy) []Grant {
	var out []Grant
	seen := map[string]struct{}{}
	for _, p := range pols {
		if p == nil {
			continue
		}
		for i, st := range p.Statements {
			if st.Effect != policy.Allow {
				continue
			}
			id := st.ID
			if id == "" {
				id = fmt.Sprintf("statement-%d", i)
			}
			for _, res := range st.Resources {
				for _, act := range st.Actions {
					perm := clonePerm(Permission{Action: act, Resource: res, Conditions: st.Conditions})
					k := atomKey(perm)
					if _, ok := seen[k]; ok {
						continue
					}
					seen[k] = struct{}{}
					out = append(out, Grant{
						Permission: perm,
						Source:     Origin{Kind: SourceOwn, PolicyID: p.ID, StatementID: id},
					})
				}
			}
		}
	}
	return out
}

// DelegationGrants turns active, unexpired delegation grants into single-action
// grants: one per scope on the delegated resource.
func DelegationGrants(grants []theauth.DelegationGrant, now time.Time) []Grant {
	var out []Grant
	for _, g := range grants {
		if g.RevokedAt != nil && !g.RevokedAt.After(now) {
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
			continue
		}
		for _, scope := range g.Scope {
			out = append(out, Grant{
				Permission: Permission{Action: scope, Resource: g.Resource},
				Source:     Origin{Kind: SourceDelegation, ChainID: g.ID.String()},
			})
		}
	}
	return out
}

// StaticGrants is a GrantSource over a fixed list. Useful for tests and demos.
type StaticGrants []Grant

// Grants implements GrantSource.
func (s StaticGrants) Grants(context.Context, string, time.Time) ([]Grant, error) {
	return append([]Grant(nil), s...), nil
}

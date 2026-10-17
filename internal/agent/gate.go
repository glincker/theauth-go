package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	oklogulid "github.com/oklog/ulid/v2"
)

// gate.go: per agent IAM policy and rate limit enforcement. The Gate sits in
// front of every agent token mint (client credentials, token exchange,
// jwt-bearer) and answers the same question at call time through Authorize.
//
// The policy engine is an interface because the policy package imports the
// root package, so internal code cannot import it. The agentpolicy package
// provides the engine backed by policy.Evaluator.

// Policy effects reported by a PolicyEngine.
const (
	VerdictAllow    = "allow"
	VerdictDeny     = "deny"
	VerdictEscalate = "escalate"
	// VerdictNone means no statement matched (default deny).
	VerdictNone = "none"
)

// PolicyQuery is one action on one resource to evaluate.
type PolicyQuery struct {
	Action   string
	Resource string
}

// PolicyVerdict is the engine's answer for one PolicyQuery.
type PolicyVerdict struct {
	Effect      string
	PolicyID    string
	StatementID string
	Reason      string
}

// PolicyDecision is the engine's answer for a batch of queries against the
// policies attached to one agent.
type PolicyDecision struct {
	// Applies is false when no policy is attached to the agent. The gate then
	// changes nothing.
	Applies bool
	// DenyList is true when the engine runs in deny list mode: only explicit
	// denies and escalations restrict, and an unmatched action passes. False
	// means allow list mode, where an unmatched action is refused.
	DenyList bool
	// RateLimit, when non-nil, replaces the gate's configured budget for this
	// agent.
	RateLimit *ratelimit.Window
	// IDs are the sorted ids of the attached policies.
	IDs []string
	// Hash is a hex SHA-256 over the canonical attached policy documents.
	Hash string
	// Verdicts has one entry per query, in order.
	Verdicts []PolicyVerdict
}

// ClassifiedError tags an engine failure with a short, secret-free class used
// in audit events and metrics. The wrapped error is never shown to a client.
type ClassifiedError struct {
	Class string
	Err   error
}

func (e *ClassifiedError) Error() string { return e.Err.Error() }
func (e *ClassifiedError) Unwrap() error { return e.Err }

// Error classes reported for engine failures.
const (
	ErrClassResolver     = "resolver_error"
	ErrClassNoAllow      = "no_allow_statement"
	ErrClassInvalidLimit = "invalid_rate_limit"
	ErrClassInvalidDoc   = "invalid_policy"
)

func errorClass(err error) string {
	var ce *ClassifiedError
	if errors.As(err, &ce) && ce.Class != "" {
		return ce.Class
	}
	return ErrClassResolver
}

// PolicyEngine resolves the policies attached to an agent and evaluates
// queries against them. A returned error means the policies could not be
// resolved; the gate then fails closed.
type PolicyEngine interface {
	Decide(ctx context.Context, ag models.Agent, queries []PolicyQuery) (PolicyDecision, error)
}

// GateConfig builds a Gate.
type GateConfig struct {
	// Storage resolves agents by id for Authorize. Optional when only mint
	// checks are used.
	Storage Storage
	// Engine evaluates attached policies. Nil disables policy checks.
	Engine PolicyEngine
	// RateLimit bounds mints and authorize calls per agent id. The zero value
	// disables it.
	RateLimit ratelimit.Window
	// MaxKeys bounds the rate limiter's memory. Defaults to
	// ratelimit.DefaultWindowMaxKeys.
	MaxKeys int
	// Audit receives denial events. Optional.
	Audit audit.Emitter
	// Now is the limiter clock. Optional.
	Now func() time.Time
	// Hooks receives the resolver failure counter. Optional.
	Hooks *obs.Hooks
}

// Gate enforces agent policies and rate limits.
type Gate struct {
	storage Storage
	engine  PolicyEngine
	limiter *ratelimit.WindowLimiter
	audit   audit.Emitter
	hooks   *obs.Hooks
	def     ratelimit.Window
}

// NewGate builds a Gate. It returns nil when neither an engine nor a rate
// limit is configured, so callers can leave the gate unset and keep their
// behavior unchanged.
func NewGate(cfg GateConfig) *Gate {
	if cfg.Engine == nil && !cfg.RateLimit.Enabled() {
		return nil
	}
	em := cfg.Audit
	if em == nil {
		em = audit.NoopEmitter{}
	}
	g := &Gate{storage: cfg.Storage, engine: cfg.Engine, audit: em, hooks: cfg.Hooks, def: cfg.RateLimit}
	g.limiter = ratelimit.NewWindowLimiter(cfg.RateLimit, cfg.MaxKeys, cfg.Now)
	return g
}

// CheckRate spends one unit of the agent's budget under the limit the agent
// last used (the configured one until a per agent override has been seen). It
// returns *models.AgentRateLimitedError when the budget is used up.
func (g *Gate) CheckRate(ctx context.Context, agentID string) error {
	if g == nil || g.limiter == nil {
		return nil
	}
	ok, retry := g.limiter.AllowCurrent(agentID)
	return g.limited(ctx, agentID, ok, retry)
}

// spend takes one unit under an explicit per agent window (override) or the
// default.
func (g *Gate) spend(ctx context.Context, agentID string, override *ratelimit.Window) error {
	if g == nil || g.limiter == nil {
		return nil
	}
	return g.rateResult(ctx, agentID, override)
}

func (g *Gate) rateResult(ctx context.Context, agentID string, override *ratelimit.Window) error {
	var ok bool
	var retry time.Duration
	if override != nil {
		ok, retry = g.limiter.AllowWith(agentID, *override)
	} else {
		ok, retry = g.limiter.Allow(agentID)
	}
	return g.limited(ctx, agentID, ok, retry)
}

func (g *Gate) limited(ctx context.Context, agentID string, ok bool, retry time.Duration) error {
	if ok {
		return nil
	}
	g.audit.EmitAudit(ctx, "agent.rate_limited", models.TargetRef{Type: "agent", ID: agentID}, map[string]any{
		"agent_id":            agentID,
		"retry_after_seconds": int(retry.Seconds()),
	})
	return &models.AgentRateLimitedError{RetryAfter: retry}
}

// engineFailed audits and counts a fail closed engine error. The audit event
// and metric carry the error class, never the raw error text.
func (g *Gate) engineFailed(ctx context.Context, ag models.Agent, grant string, err error) error {
	class := errorClass(err)
	g.audit.EmitAudit(ctx, "agent.policy_resolver_failed", models.TargetRef{Type: "agent", ID: ag.ID.String()}, map[string]any{
		"agent_id":    ag.ID.String(),
		"client_id":   ag.ClientID,
		"grant":       grant,
		"error_class": class,
	})
	g.hooks.Counter(obs.MetricAgentPolicyResolverErrors, obs.Labels{obs.AttrGrantType: grant}).Inc()
	return fmt.Errorf("%w: resolve policies for agent %s: %w", models.ErrOAuthServerBusy, ag.ID, err)
}

// AuthorizeMint vets one token mint for ag. See models.AgentMintRequest for
// how explicit and defaulted scopes differ.
func (g *Gate) AuthorizeMint(ctx context.Context, ag models.Agent, req models.AgentMintRequest) (models.AgentMintResult, error) {
	res := models.AgentMintResult{Scopes: slices.Clone(req.Scopes)}
	if g == nil {
		return res, nil
	}
	if g.engine == nil {
		if err := g.spend(ctx, ag.ID.String(), nil); err != nil {
			return models.AgentMintResult{}, err
		}
		return res, nil
	}
	queries := make([]PolicyQuery, len(req.Scopes))
	for i, sc := range req.Scopes {
		queries[i] = PolicyQuery{Action: sc, Resource: req.Resource}
	}
	dec, err := g.engine.Decide(ctx, ag, queries)
	if err != nil {
		// Fail closed: an unresolvable policy never widens access. The cause
		// stays in the log chain, the wire shows temporarily_unavailable.
		return models.AgentMintResult{}, g.engineFailed(ctx, ag, req.Grant, err)
	}
	if err := g.spend(ctx, ag.ID.String(), dec.RateLimit); err != nil {
		return models.AgentMintResult{}, err
	}
	if !dec.Applies {
		return res, nil
	}
	if len(dec.Verdicts) != len(queries) {
		return models.AgentMintResult{}, fmt.Errorf("%w: policy engine returned %d verdicts for %d queries", models.ErrOAuthServerBusy, len(dec.Verdicts), len(queries))
	}
	res.PolicyIDs = dec.IDs
	res.PolicyHash = dec.Hash
	kept := make([]string, 0, len(req.Scopes))
	var firstDenied *PolicyVerdict
	firstDeniedAction := ""
	for i, sc := range req.Scopes {
		v := dec.Verdicts[i]
		denyList := dec.DenyList
		if req.Ceiling != nil && !slices.Contains(req.Ceiling, sc) {
			// A deny list never widens past the registered scope ceiling.
			v, denyList = PolicyVerdict{Effect: VerdictNone, Reason: "outside registered scope ceiling"}, false
		}
		if permits(v, denyList) {
			kept = append(kept, sc)
			continue
		}
		if req.Explicit {
			return models.AgentMintResult{}, g.refuse(ctx, ag, req, sc, v, dec)
		}
		res.Dropped = append(res.Dropped, sc)
		if firstDenied == nil {
			vv := v
			firstDenied, firstDeniedAction = &vv, sc
		}
	}
	if len(kept) == 0 && firstDenied != nil {
		return models.AgentMintResult{}, g.refuse(ctx, ag, req, firstDeniedAction, *firstDenied, dec)
	}
	res.Scopes = kept
	return res, nil
}

// permits reports whether a verdict lets the action through.
func permits(v PolicyVerdict, denyList bool) bool {
	switch v.Effect {
	case VerdictAllow:
		return true
	case VerdictNone:
		return denyList
	}
	return false
}

// refuse audits and builds the client safe error for a refused action.
func (g *Gate) refuse(ctx context.Context, ag models.Agent, req models.AgentMintRequest, action string, v PolicyVerdict, dec PolicyDecision) error {
	g.audit.EmitAudit(ctx, "agent.token_denied", models.TargetRef{Type: "agent", ID: ag.ID.String()}, map[string]any{
		"agent_id":     ag.ID.String(),
		"grant":        req.Grant,
		"resource":     req.Resource,
		"action":       action,
		"effect":       v.Effect,
		"policy_id":    v.PolicyID,
		"statement_id": v.StatementID,
		"agent_policy": map[string]any{"ids": dec.IDs, "hash": dec.Hash},
	})
	if v.Effect == VerdictNone {
		return fmt.Errorf("%w: scope %q is not permitted by agent policy", models.ErrOAuthInvalidScope, action)
	}
	return &models.AgentPolicyDeniedError{
		Action: action, Resource: req.Resource, PolicyID: v.PolicyID, StatementID: v.StatementID, Reason: v.Reason,
	}
}

// ErrAgentNotActive is returned by Authorize for an unknown or inactive agent.
var ErrAgentNotActive = errors.New("theauth: agent not active")

// Authorize answers, at call time, whether the agent may perform action on
// resource under its attached policies. It spends one unit of the agent's rate
// budget. With no policy attached it permits the call. It returns
// *models.AgentPolicyDeniedError on a refusal and *models.AgentRateLimitedError
// when the budget is used up. Resolver failures and unknown agents fail closed.
func (g *Gate) Authorize(ctx context.Context, agentID, action, resource string) error {
	if g == nil {
		return nil
	}
	if g.engine == nil {
		return g.spend(ctx, agentID, nil)
	}
	if g.storage == nil {
		return fmt.Errorf("%w: no agent storage", ErrAgentNotActive)
	}
	id, err := oklogulid.Parse(agentID)
	if err != nil {
		return fmt.Errorf("%w: malformed agent id", ErrAgentNotActive)
	}
	ag, err := g.storage.AgentByID(ctx, id)
	if err != nil || ag == nil || ag.Status != models.AgentStatusActive {
		return fmt.Errorf("%w: %s", ErrAgentNotActive, agentID)
	}
	dec, err := g.engine.Decide(ctx, *ag, []PolicyQuery{{Action: action, Resource: resource}})
	if err != nil {
		return g.engineFailed(ctx, *ag, "authorize", err)
	}
	if err := g.spend(ctx, agentID, dec.RateLimit); err != nil {
		return err
	}
	if !dec.Applies {
		return nil
	}
	if len(dec.Verdicts) != 1 {
		return fmt.Errorf("theauth: policy engine returned %d verdicts for 1 query", len(dec.Verdicts))
	}
	v := dec.Verdicts[0]
	if permits(v, dec.DenyList) {
		return nil
	}
	g.audit.EmitAudit(ctx, "agent.authorize_denied", models.TargetRef{Type: "agent", ID: agentID}, map[string]any{
		"agent_id":     agentID,
		"action":       action,
		"resource":     resource,
		"effect":       v.Effect,
		"policy_id":    v.PolicyID,
		"statement_id": v.StatementID,
		"agent_policy": map[string]any{"ids": dec.IDs, "hash": dec.Hash},
	})
	return &models.AgentPolicyDeniedError{
		Action: action, Resource: resource, PolicyID: v.PolicyID, StatementID: v.StatementID, Reason: v.Reason,
	}
}

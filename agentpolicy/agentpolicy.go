// Package agentpolicy attaches IAM policy documents to agents so the library,
// not a prompt, decides what an agent may do.
//
// Build an Engine from the host's policy documents and hand it to
// theauth.AgentConfig.PolicyEngine. Every agent token mint (client
// credentials, token exchange, jwt-bearer) is then evaluated against the
// agent's policies: an explicit Deny fails the mint with access_denied, scopes
// no Allow statement covers are narrowed away, and the ids and hash of the
// policies in force are recorded in the token and the audit event.
//
// The same Engine answers the call time question through Policies, which
// plugs into policy/toolguard.Guard, and through (*theauth.TheAuth).AuthorizeAgent.
//
// An agent with no attached policy is not restricted, so adopting the package
// changes nothing until a policy is attached.
package agentpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/oklog/ulid/v2"
)

// Resolver returns the policies attached to one agent. It is the host's hook
// into its own IAM store. An error makes every mint for that agent fail
// closed (the client sees temporarily_unavailable).
type Resolver func(ctx context.Context, ag theauth.Agent) ([]policy.Policy, error)

// Resolution is what ResolverV2 returns for one agent.
type Resolution struct {
	// Policies are attached to the agent, after Config.Policies.
	Policies []policy.Policy
	// RateLimit, when non-nil, replaces the configured AgentConfig.RateLimit
	// for this agent. It must have Requests > 0; Per defaults to one minute and
	// Burst to Requests. An invalid value fails the mint closed.
	RateLimit *theauth.AgentRateLimit
}

// ResolverV2 returns the policies and an optional rate limit for one agent.
type ResolverV2 func(ctx context.Context, ag theauth.Agent) (Resolution, error)

// Mode says how an action that no statement matches is treated.
type Mode int

const (
	// AllowList is the default. Nothing is permitted unless an allow
	// statement covers it, so a policy set with no allow statement is an
	// error, not an open door.
	AllowList Mode = iota
	// DenyList permits what no statement matches. Only deny and escalate
	// statements restrict. Grants are still capped by the agent's registered
	// scopes, the resource catalog and the delegation, so a deny list never
	// widens access; it only narrows it.
	DenyList
)

// Errors reported by the engine. Mint failures wrap them, so errors.Is works.
var (
	// ErrNoAllowStatement means an AllowList engine was given policies with
	// no allow statement.
	ErrNoAllowStatement = errors.New("agentpolicy: allow list mode needs at least one allow statement (use DenyList mode for a deny only policy)")
	// ErrInvalidRateLimit means a resolver returned an unusable rate limit.
	ErrInvalidRateLimit = errors.New("agentpolicy: invalid per agent rate limit")
)

// Config builds an Engine.
type Config struct {
	// Policies apply to every agent, before the resolver's policies. Use them
	// for fleet wide rules such as a shared denylist.
	Policies []policy.Policy
	// Resolver returns per agent policies. Optional. Ignored when ResolverV2
	// is set.
	Resolver Resolver
	// ResolverV2 returns per agent policies and an optional per agent rate
	// limit. When both resolvers are set, ResolverV2 wins.
	ResolverV2 ResolverV2
	// Mode is AllowList (zero value) or DenyList.
	Mode Mode
	// Evaluator evaluates requests. The zero value is ready; set Now, Risk or
	// Taint to customize.
	Evaluator policy.Evaluator
}

// Engine evaluates agents against their attached policies. It implements
// theauth.AgentPolicyEngine.
type Engine struct {
	base     []*policy.Policy
	resolver ResolverV2
	mode     Mode
	eval     policy.Evaluator
}

// New validates the configured policies and builds an Engine. In AllowList
// mode it rejects static policies that hold no allow statement when no
// resolver could add one.
func New(cfg Config) (*Engine, error) {
	e := &Engine{mode: cfg.Mode, eval: cfg.Evaluator}
	switch {
	case cfg.ResolverV2 != nil:
		e.resolver = cfg.ResolverV2
	case cfg.Resolver != nil:
		old := cfg.Resolver
		e.resolver = func(ctx context.Context, ag theauth.Agent) (Resolution, error) {
			ps, err := old(ctx, ag)
			return Resolution{Policies: ps}, err
		}
	}
	for i := range cfg.Policies {
		p := cfg.Policies[i]
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("agentpolicy: policy %d: %w", i, err)
		}
		e.base = append(e.base, &p)
	}
	if cfg.Mode == AllowList && len(e.base) > 0 && e.resolver == nil && !hasAllow(e.base) {
		return nil, ErrNoAllowStatement
	}
	return e, nil
}

func hasAllow(pols []*policy.Policy) bool {
	for _, p := range pols {
		for _, s := range p.Statements {
			if s.Effect == policy.Allow {
				return true
			}
		}
	}
	return false
}

// Decide implements the internal engine contract.
func (e *Engine) Decide(ctx context.Context, ag theauth.Agent, queries []agent.PolicyQuery) (agent.PolicyDecision, error) {
	pols, limit, err := e.resolve(ctx, ag)
	if err != nil {
		return agent.PolicyDecision{}, err
	}
	dec := agent.PolicyDecision{RateLimit: limit, DenyList: e.mode == DenyList}
	if len(pols) == 0 {
		return dec, nil
	}
	if e.mode == AllowList && !hasAllow(pols) {
		return agent.PolicyDecision{}, &agent.ClassifiedError{Class: agent.ErrClassNoAllow, Err: ErrNoAllowStatement}
	}
	dec.Applies = true
	dec.Verdicts = make([]agent.PolicyVerdict, len(queries))
	dec.IDs, dec.Hash = digest(pols)
	attrs := map[string]string{"agent_id": ag.ID.String(), "client_id": ag.ClientID}
	for i, q := range queries {
		d := e.eval.Evaluate(policy.Request{Action: q.Action, Resource: q.Resource, Attributes: attrs}, pols...)
		dec.Verdicts[i] = verdict(d)
	}
	return dec, nil
}

func verdict(d policy.Decision) agent.PolicyVerdict {
	v := agent.PolicyVerdict{PolicyID: d.PolicyID, StatementID: d.StatementID, Reason: d.Reason}
	switch d.Effect {
	case policy.Allow:
		v.Effect = agent.VerdictAllow
	case policy.Deny:
		v.Effect = agent.VerdictDeny
	case policy.Escalate:
		v.Effect = agent.VerdictEscalate
	default:
		// No statement matched. A taint or risk driven refusal of an allowed
		// request has an empty Effect with a reason; treat it as a deny.
		v.Effect = agent.VerdictNone
		if d.PolicyID != "" || d.Taint != nil {
			v.Effect = agent.VerdictDeny
		}
	}
	return v
}

// resolve returns the base plus resolved policies and the optional per agent
// rate limit. Every failure carries an error class for audit and metrics.
func (e *Engine) resolve(ctx context.Context, ag theauth.Agent) ([]*policy.Policy, *ratelimit.Window, error) {
	out := slices.Clone(e.base)
	if e.resolver == nil {
		return out, nil, nil
	}
	res, err := e.resolver(ctx, ag)
	if err != nil {
		return nil, nil, &agent.ClassifiedError{Class: agent.ErrClassResolver, Err: fmt.Errorf("agentpolicy: resolver: %w", err)}
	}
	for i := range res.Policies {
		p := res.Policies[i]
		if err := p.Validate(); err != nil {
			return nil, nil, &agent.ClassifiedError{Class: agent.ErrClassInvalidDoc, Err: fmt.Errorf("agentpolicy: resolver returned invalid policy %d: %w", i, err)}
		}
		out = append(out, &p)
	}
	if res.RateLimit == nil {
		return out, nil, nil
	}
	n, err := res.RateLimit.Normalize()
	if err != nil {
		return nil, nil, &agent.ClassifiedError{Class: agent.ErrClassInvalidLimit, Err: fmt.Errorf("%w: %w", ErrInvalidRateLimit, err)}
	}
	return out, &ratelimit.Window{Requests: n.Requests, Per: n.Per, Burst: n.Burst}, nil
}

// digest returns the sorted policy ids and a SHA-256 over the canonical JSON of
// every document, in order.
func digest(pols []*policy.Policy) ([]string, string) {
	h := sha256.New()
	var ids []string
	for _, p := range pols {
		b, err := json.Marshal(p)
		if err == nil {
			h.Write(b)
			h.Write([]byte{0})
		}
		if p.ID != "" {
			ids = append(ids, p.ID)
		}
	}
	sort.Strings(ids)
	return slices.Compact(ids), hex.EncodeToString(h.Sum(nil))
}

// Policies returns a function for toolguard.Guard.Policies that resolves the
// same policies the engine uses at mint time, so the guard and the token
// endpoint cannot drift. It needs the agent row, so it takes the TheAuth
// instance to look the agent up.
func (e *Engine) Policies(a *theauth.TheAuth) func(ctx context.Context, agentID string) ([]*policy.Policy, error) {
	return func(ctx context.Context, agentID string) ([]*policy.Policy, error) {
		id, err := ulid.Parse(agentID)
		if err != nil {
			return nil, fmt.Errorf("agentpolicy: malformed agent id %q: %w", agentID, err)
		}
		ag, err := a.GetAgent(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("agentpolicy: load agent %s: %w", agentID, err)
		}
		pols, _, err := e.resolve(ctx, *ag)
		return pols, err
	}
}

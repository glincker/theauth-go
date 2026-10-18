package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

// Request is one authorization question. Attributes feed {var} substitution
// and condition keys; the reserved key "ip" is also read from IP.
type Request struct {
	Action     string
	Resource   string
	Attributes map[string]string
	IP         string
	Now        time.Time
	// Typed risk attributes. They feed Evaluator.Risk tier matching.
	Amount       float64
	Currency     string
	DataClass    string
	Irreversible bool
	// Provenance holds the labels of the call's arguments, keyed by argument
	// name. The key CallLabelsKey labels the whole call. It feeds
	// Evaluator.Taint. Nil means no provenance was supplied.
	Provenance map[string][]string

	// matching is Evaluator.ResourceMatching, copied in by prepare so statement matching can see it.
	matching pathmatch.Mode
}

// Decision is the audited outcome of an evaluation.
type Decision struct {
	// Allowed is true only when Effect is Allow. Escalate and deny are both
	// false, so existing callers that gate on Allowed stay safe.
	Allowed     bool   `json:"allowed"`
	Effect      Effect `json:"effect,omitempty"`
	PolicyID    string `json:"policyId,omitempty"`
	StatementID string `json:"statementId,omitempty"`
	Reason      string `json:"reason"`
	// Code is the machine-readable outcome. It is set on every decision the
	// evaluator produces; see DecisionCode.
	Code     DecisionCode `json:"code"`
	Boundary bool         `json:"boundary,omitempty"`
	// Escalation is set when Effect is Escalate.
	Escalation *Escalation `json:"escalation,omitempty"`
	// Taint is the taint verdict, set when provenance was supplied or a rule
	// with Unlabeled "violate" applied. Nil otherwise.
	Taint *TaintVerdict `json:"taint,omitempty"`
}

// Evaluator evaluates requests against policies. The zero value is ready.
type Evaluator struct {
	// Now supplies the clock for conditions when Request.Now is zero.
	Now func() time.Time
	// Risk maps request risk attributes to tiers that can escalate an
	// otherwise allowed request. Empty means no risk tiers.
	Risk []RiskTier
	// Taint restricts which provenance labels may flow into which tools. It is
	// applied after risk tiers. Empty means no taint rules.
	Taint []TaintRule
	// ResourceMatching selects how a statement or taint rule resource compares to the request
	// resource. The zero value keeps the glob matcher (Match): "*" is any run of bytes. Set
	// pathmatch.Path for the colon and path aware matcher shared with the TypeScript core
	// (resourceMatching "path"): ":" separates segments, "/" separates path segments inside one,
	// "*" is one segment and "**" one or more, never an empty, "." or ".." one. In that mode a
	// partial glob such as "r*" is literal text. Action patterns keep using Match.
	ResourceMatching pathmatch.Mode
}

// Evaluate applies explicit-deny-wins then default-deny across policies.
func (e Evaluator) Evaluate(req Request, policies ...*Policy) Decision {
	req = e.prepare(req)
	return e.applyTaint(req, e.evaluate(req, policies...))
}

func (e Evaluator) evaluate(req Request, policies ...*Policy) Decision {
	var allow, escalate *Decision
	for _, p := range policies {
		if p == nil {
			continue
		}
		for i, s := range p.Statements {
			if !s.matches(req) {
				continue
			}
			d := Decision{Effect: s.Effect, PolicyID: p.ID, StatementID: s.ID}
			if s.Effect == Deny {
				if d.StatementID == "" {
					d.StatementID = statementIndexID(i)
				}
				d.Reason = "explicit deny"
				d.Code = CodeNoPermission
				return d
			}
			if s.Effect == Escalate {
				if escalate == nil {
					if d.StatementID == "" {
						d.StatementID = statementIndexID(i)
					}
					d.Reason = "escalation required by statement"
					d.Code = CodeApprovalRequired
					d.Escalation = &Escalation{Tier: s.Tier, Requirement: s.Require, Reason: d.Reason}
					if d.Escalation.Requirement == "" {
						d.Escalation.Requirement = RequireApproval
					}
					escalate = &d
				}
				continue
			}
			if allow == nil {
				if d.StatementID == "" {
					d.StatementID = statementIndexID(i)
				}
				d.Allowed = true
				d.Reason = "allowed by statement"
				d.Code = CodeAllowed
				allow = &d
			}
		}
	}
	if escalate != nil {
		return *escalate
	}
	if allow != nil {
		return e.applyRisk(req, *allow)
	}
	return Decision{Reason: "no matching allow statement (default deny)", Code: e.defaultDenyCode(req, policies)}
}

// defaultDenyCode refines a default deny: when an allow statement covered the
// action and resource but a source IP or time window condition failed, the
// code says so instead of the generic no_permission. The first such
// statement in policy order wins.
func (e Evaluator) defaultDenyCode(req Request, policies []*Policy) DecisionCode {
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, s := range p.Statements {
			if s.Effect != Allow || !s.matchesTarget(req) {
				continue
			}
			for _, c := range s.Conditions {
				if c.holds(req) {
					continue
				}
				switch c.Op {
				case OpIPCIDR, OpNotIPCIDR:
					return CodeIPNotAllowed
				case OpTimeWindow, OpDailyWindow:
					return CodeTimeRestricted
				}
			}
		}
	}
	return CodeNoPermission
}

// statementIndexID is the StatementID given to an unnamed statement: its
// position within the policy document. Built only for the statement that is
// actually returned, so non-selected matches do not allocate.
func statementIndexID(i int) string {
	return fmt.Sprintf("stmt-%d", i)
}

// EvaluateWithBoundary requires identity policies to allow and the boundary
// policies, when any exist, to allow as well, so a boundary only narrows.
func (e Evaluator) EvaluateWithBoundary(req Request, identity, boundary []*Policy) Decision {
	d := e.Evaluate(req, identity...)
	if !d.Allowed || len(boundary) == 0 {
		return d
	}
	b := e.evaluate(e.prepare(req), boundary...)
	if !b.Allowed {
		b.Boundary = true
		b.Reason = "permission boundary: " + b.Reason
		return b
	}
	return d
}

func (e Evaluator) prepare(req Request) Request {
	req.matching = e.ResourceMatching
	if req.Now.IsZero() {
		if e.Now != nil {
			req.Now = e.Now()
		} else {
			req.Now = time.Now()
		}
	}
	return req
}

func (s Statement) matches(req Request) bool {
	if !s.matchesTarget(req) {
		return false
	}
	for _, c := range s.Conditions {
		if !c.holds(req) {
			return false
		}
	}
	return true
}

// matchesTarget reports whether the statement covers the request's action and
// resource, ignoring conditions.
func (s Statement) matchesTarget(req Request) bool {
	if !slices.ContainsFunc(s.Actions, func(p string) bool { return Match(p, req.Action) }) {
		return false
	}
	// A deny whose variables cannot be resolved still applies (fail closed).
	return s.matchesResource(req, s.Effect == Deny)
}

func (s Statement) matchesResource(req Request, unresolvedMatches bool) bool {
	for _, pat := range s.Resources {
		exp, ok := expand(pat, req.Attributes, true)
		if !ok {
			if unresolvedMatches {
				return true
			}
			continue
		}
		if req.matchResource(exp) {
			return true
		}
	}
	return false
}

// matchResource compares an expanded resource pattern with the request resource in the mode the
// evaluator was configured with.
func (r Request) matchResource(pattern string) bool {
	if r.matching == pathmatch.Path {
		return pathmatch.MatchPath(pattern, r.Resource)
	}
	return Match(pattern, r.Resource)
}

func (c Condition) holds(req Request) bool {
	switch c.Op {
	case OpTimeWindow:
		return inAbsoluteWindow(c.Values, req.Now)
	case OpDailyWindow:
		return inDailyWindow(c.Values, req.Now)
	}
	val, present := req.Attributes[c.Key]
	if c.Key == "ip" {
		val, present = req.IP, req.IP != ""
	}
	want := make([]string, 0, len(c.Values))
	for _, v := range c.Values {
		x, ok := expand(v, req.Attributes, false)
		if ok {
			want = append(want, x)
		}
	}
	switch c.Op {
	case OpEquals:
		return present && len(want) == 1 && val == want[0]
	case OpNotEquals:
		return !present || len(want) != 1 || val != want[0]
	case OpIn:
		return present && slices.Contains(want, val)
	case OpNotIn:
		return !present || !slices.Contains(want, val)
	case OpIPCIDR:
		return present && inCIDR(c.Values, val)
	case OpNotIPCIDR:
		return !present || !inCIDR(c.Values, val)
	}
	return false
}

func inCIDR(cidrs []string, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

func inAbsoluteWindow(v []string, now time.Time) bool {
	if len(v) != 2 {
		return false
	}
	if v[0] != "" {
		start, err := time.Parse(time.RFC3339, v[0])
		if err != nil || now.Before(start) {
			return false
		}
	}
	if v[1] != "" {
		end, err := time.Parse(time.RFC3339, v[1])
		if err != nil || !now.Before(end) {
			return false
		}
	}
	return true
}

func inDailyWindow(v []string, now time.Time) bool {
	if len(v) != 2 {
		return false
	}
	start, err1 := parseClock(v[0])
	end, err2 := parseClock(v[1])
	if err1 != nil || err2 != nil {
		return false
	}
	u := now.UTC()
	cur := u.Hour()*60 + u.Minute()
	if start <= end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}

package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Request is one authorization question. Attributes feed {var} substitution
// and condition keys; the reserved key "ip" is also read from IP.
type Request struct {
	Action     string
	Resource   string
	Attributes map[string]string
	IP         string
	Now        time.Time
}

// Decision is the audited outcome of an evaluation.
type Decision struct {
	Allowed     bool   `json:"allowed"`
	Effect      Effect `json:"effect,omitempty"`
	PolicyID    string `json:"policyId,omitempty"`
	StatementID string `json:"statementId,omitempty"`
	Reason      string `json:"reason"`
	Boundary    bool   `json:"boundary,omitempty"`
}

// Evaluator evaluates requests against policies. The zero value is ready.
type Evaluator struct {
	// Now supplies the clock for conditions when Request.Now is zero.
	Now func() time.Time
}

// Evaluate applies explicit-deny-wins then default-deny across policies.
func (e Evaluator) Evaluate(req Request, policies ...*Policy) Decision {
	req = e.prepare(req)
	var allow *Decision
	for _, p := range policies {
		if p == nil {
			continue
		}
		for i, s := range p.Statements {
			if !s.matches(req) {
				continue
			}
			d := Decision{Effect: s.Effect, PolicyID: p.ID, StatementID: s.ID}
			if d.StatementID == "" {
				d.StatementID = fmt.Sprintf("stmt-%d", i)
			}
			if s.Effect == Deny {
				d.Reason = "explicit deny"
				return d
			}
			if allow == nil {
				d.Allowed = true
				d.Reason = "allowed by statement"
				allow = &d
			}
		}
	}
	if allow != nil {
		return *allow
	}
	return Decision{Reason: "no matching allow statement (default deny)"}
}

// EvaluateWithBoundary requires identity policies to allow and the boundary
// policies, when any exist, to allow as well, so a boundary only narrows.
func (e Evaluator) EvaluateWithBoundary(req Request, identity, boundary []*Policy) Decision {
	d := e.Evaluate(req, identity...)
	if !d.Allowed || len(boundary) == 0 {
		return d
	}
	b := e.Evaluate(req, boundary...)
	if !b.Allowed {
		b.Boundary = true
		b.Reason = "permission boundary: " + b.Reason
		return b
	}
	return d
}

func (e Evaluator) prepare(req Request) Request {
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
	if !slices.ContainsFunc(s.Actions, func(p string) bool { return Match(p, req.Action) }) {
		return false
	}
	// A deny whose variables cannot be resolved still applies (fail closed).
	failOpen := s.Effect == Deny
	if !s.matchesResource(req, failOpen) {
		return false
	}
	for _, c := range s.Conditions {
		if !c.holds(req) {
			return false
		}
	}
	return true
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
		if Match(exp, req.Resource) {
			return true
		}
	}
	return false
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

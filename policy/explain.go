package policy

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
)

// MaxNearMisses caps Explanation.NearMisses.
const MaxNearMisses = 3

// Mismatch kinds reported on a NearMiss.
const (
	MismatchResource  = "resource"
	MismatchAction    = "action"
	MismatchCondition = "condition"
)

// Explanation says what Evaluate decides for a request and why. It is built
// from Evaluate itself, so Decision and Code can never drift from the real
// outcome. Building one is read only: it writes no audit rows, bumps no
// counters and spends no approvals.
type Explanation struct {
	// Decision is exactly what Evaluator.Evaluate returns for the request.
	Decision Decision `json:"decision"`
	// Code is Decision.Code, repeated for convenience.
	Code DecisionCode `json:"code"`
	// Matched is the statement that decided the request. Nil on a default deny.
	Matched *MatchedStatement `json:"matched,omitempty"`
	// Conditions lists the conditions that were checked. For a matched
	// statement every entry passed. For a default deny it holds the conditions
	// that failed on statements covering the action and resource.
	Conditions []ConditionResult `json:"conditions,omitempty"`
	// NearMisses are the closest statements that almost allowed a request that
	// was default denied, best first, at most MaxNearMisses.
	NearMisses []NearMiss `json:"nearMisses,omitempty"`
}

// MatchedStatement identifies the deciding statement.
type MatchedStatement struct {
	PolicyID    string `json:"policyId,omitempty"`
	StatementID string `json:"statementId"`
	Effect      Effect `json:"effect"`
}

// ConditionResult is one evaluated condition.
type ConditionResult struct {
	PolicyID    string   `json:"policyId,omitempty"`
	StatementID string   `json:"statementId"`
	Op          string   `json:"op"`
	Key         string   `json:"key,omitempty"`
	Values      []string `json:"values,omitempty"`
	Passed      bool     `json:"passed"`
	// Detail is a short human sentence, for example the offending address.
	Detail string `json:"detail"`
}

// NearMiss is an allow or escalate statement that almost matched.
type NearMiss struct {
	PolicyID    string `json:"policyId,omitempty"`
	StatementID string `json:"statementId"`
	// Mismatch lists what differed: resource, action and or condition.
	Mismatch []string `json:"mismatch"`
	// Hint is a short human description of the gap.
	Hint string `json:"hint"`
	// Score is in 0..1: 0.6 times the resource segment overlap plus 0.4 when
	// the action matched. A statement that covers the action and resource and
	// fails only on a condition scores 0.9.
	Score float64 `json:"score"`
}

// Explain is Evaluator{}.Explain.
func Explain(req Request, policies ...*Policy) Explanation {
	return Evaluator{}.Explain(req, policies...)
}

// Explain evaluates req exactly as Evaluate does and adds the reasoning.
func (e Evaluator) Explain(req Request, policies ...*Policy) Explanation {
	d := e.Evaluate(req, policies...)
	req = e.prepare(req)
	x := Explanation{Decision: d, Code: d.Code}
	if d.StatementID != "" {
		x.Matched = &MatchedStatement{PolicyID: d.PolicyID, StatementID: d.StatementID, Effect: d.Effect}
		if d.Effect == "" {
			x.Matched.Effect = Allow
		}
		if p, s, ok := findDecided(d, req, policies); ok {
			for _, c := range s.Conditions {
				x.Conditions = append(x.Conditions, conditionResult(p.ID, d.StatementID, c, req))
			}
		}
		return x
	}
	if d.Effect != "" || d.Allowed {
		return x
	}
	for _, p := range nonNil(policies) {
		for i, s := range p.Statements {
			if s.Effect != Allow || !s.matchesTarget(req) {
				continue
			}
			for _, c := range s.Conditions {
				if r := conditionResult(p.ID, stmtID(s, i), c, req); !r.Passed {
					x.Conditions = append(x.Conditions, r)
				}
			}
		}
	}
	x.NearMisses = nearMisses(req, policies)
	return x
}

func nonNil(policies []*Policy) []*Policy {
	return slices.DeleteFunc(slices.Clone(policies), func(p *Policy) bool { return p == nil })
}

func stmtID(s Statement, i int) string {
	if s.ID != "" {
		return s.ID
	}
	return statementIndexID(i)
}

// findDecided locates the statement named by the decision. Policy ids are not
// required to be unique, so the statement must also match the request.
func findDecided(d Decision, req Request, policies []*Policy) (*Policy, Statement, bool) {
	for _, p := range nonNil(policies) {
		if p.ID != d.PolicyID {
			continue
		}
		for i, s := range p.Statements {
			if stmtID(s, i) == d.StatementID && s.matches(req) {
				return p, s, true
			}
		}
	}
	return nil, Statement{}, false
}

func conditionResult(policyID, statement string, c Condition, req Request) ConditionResult {
	r := ConditionResult{
		PolicyID: policyID, StatementID: statement, Op: c.Op, Key: c.Key,
		Values: slices.Clone(c.Values), Passed: c.holds(req),
	}
	state := "failed"
	if r.Passed {
		state = "held"
	}
	switch c.Op {
	case OpIPCIDR, OpNotIPCIDR:
		ip := req.IP
		if c.Key != "ip" {
			ip = req.Attributes[c.Key]
		}
		if ip == "" {
			ip = "(none)"
		}
		r.Detail = fmt.Sprintf("source ip %s %s %s %s", ip, state, c.Op, strings.Join(c.Values, ","))
	case OpTimeWindow, OpDailyWindow:
		r.Detail = fmt.Sprintf("time %s %s %s [%s]", req.Now.UTC().Format("2006-01-02T15:04:05Z"), state, c.Op, strings.Join(c.Values, ", "))
	default:
		got, ok := req.Attributes[c.Key]
		if !ok {
			got = "(unset)"
		}
		r.Detail = fmt.Sprintf("attribute %s=%s %s %s [%s]", c.Key, got, state, c.Op, strings.Join(c.Values, ", "))
	}
	return r
}

// nearMisses ranks allow and escalate statements that did not match. A
// statement is a candidate when its action matched, or its resource shares at
// least one leading segment with the request.
func nearMisses(req Request, policies []*Policy) []NearMiss {
	var found []NearMiss
	for _, p := range nonNil(policies) {
		for i, s := range p.Statements {
			if s.Effect == Deny || s.matches(req) {
				continue
			}
			actionOK := slices.ContainsFunc(s.Actions, func(a string) bool { return Match(a, req.Action) })
			resourceOK := s.matchesResource(req, false)
			overlap, best := 0.0, ""
			for _, pat := range s.Resources {
				exp, _ := expand(pat, req.Attributes, true)
				if o := segmentOverlap(exp, req.Resource); best == "" || o > overlap {
					overlap, best = o, exp
				}
			}
			if overlap == 0 && !actionOK {
				continue
			}
			var mm []string
			if !resourceOK {
				mm = append(mm, MismatchResource)
			}
			if !actionOK {
				mm = append(mm, MismatchAction)
			}
			if resourceOK && actionOK {
				mm = append(mm, MismatchCondition)
			}
			score := 0.6 * overlap
			if actionOK {
				score += 0.4
			}
			if resourceOK && actionOK {
				score = 0.9
			}
			found = append(found, NearMiss{
				PolicyID: p.ID, StatementID: stmtID(s, i), Mismatch: mm,
				Hint:  hint(s, req, best, mm),
				Score: math.Round(score*100) / 100,
			})
		}
	}
	sort.SliceStable(found, func(a, b int) bool { return found[a].Score > found[b].Score })
	if len(found) > MaxNearMisses {
		found = found[:MaxNearMisses]
	}
	return found
}

// segmentOverlap is the share of leading "/" segments the pattern covers,
// using the evaluator's own Match per segment. A full match scores 1.
func segmentOverlap(pattern, resource string) float64 {
	if Match(pattern, resource) {
		return 1
	}
	p, r := strings.Split(pattern, "/"), strings.Split(resource, "/")
	shared := 0
	for shared < len(p) && shared < len(r) && Match(p[shared], r[shared]) {
		shared++
	}
	return float64(shared) / float64(max(len(p), len(r)))
}

func hint(s Statement, req Request, pattern string, mismatch []string) string {
	var parts []string
	if slices.Contains(mismatch, MismatchResource) {
		parts = append(parts, fmt.Sprintf("resource %q does not cover %q", pattern, req.Resource))
	}
	if slices.Contains(mismatch, MismatchAction) {
		parts = append(parts, fmt.Sprintf("you hold %s on %s, this needs %s", strings.Join(s.Actions, ", "), pattern, req.Action))
	}
	if slices.Contains(mismatch, MismatchCondition) {
		parts = append(parts, "action and resource match but a condition failed")
	}
	return strings.Join(parts, "; ")
}

// String renders the explanation as short plain text for logs and test output.
func (x Explanation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s): %s", outcome(x.Decision), x.Code, x.Decision.Reason)
	if x.Matched != nil {
		fmt.Fprintf(&b, "\n  matched %s statement %q in policy %q", x.Matched.Effect, x.Matched.StatementID, x.Matched.PolicyID)
	}
	for _, c := range x.Conditions {
		fmt.Fprintf(&b, "\n  condition %q: %s", c.StatementID, c.Detail)
	}
	for _, n := range x.NearMisses {
		fmt.Fprintf(&b, "\n  near miss %q (%.2f, %s): %s", n.StatementID, n.Score, strings.Join(n.Mismatch, "+"), n.Hint)
	}
	return b.String()
}

func outcome(d Decision) string {
	switch {
	case d.Allowed:
		return "allowed"
	case d.Effect == Escalate:
		return "escalated"
	}
	return "denied"
}

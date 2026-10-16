package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CallLabelsKey is the Request.Provenance key whose labels apply to every
// argument of the call.
const CallLabelsKey = "*"

// UnlabeledMode says how a require check treats an argument with no labels.
type UnlabeledMode string

// Unlabeled modes. The zero value behaves as UnlabeledAllow.
const (
	// UnlabeledAllow skips require checks on an unlabeled argument, so a call
	// with no provenance behaves as before.
	UnlabeledAllow UnlabeledMode = "allow"
	// UnlabeledViolate fails closed: an unlabeled argument counts as missing
	// every required label.
	UnlabeledViolate UnlabeledMode = "violate"
)

// ArgRule demands things of the labels on one argument. A trailing * in a
// pattern is a prefix wildcard ("tool_output:*"); "*" matches any label.
type ArgRule struct {
	// Forbid fails when any label matches one of these patterns.
	Forbid []string `json:"forbid,omitempty"`
	// Require fails unless every pattern is matched by at least one label.
	Require []string `json:"require,omitempty"`
}

// TaintRule restricts which provenance labels may flow into a tool.
type TaintRule struct {
	// ID is copied into the verdict. Defaults to the rule index.
	ID string `json:"id,omitempty"`
	// Resource is a glob such as "tool:send_email" or "tool:*".
	Resource string `json:"resource"`
	// Actions restricts the rule to these action globs. Empty means all.
	Actions []string `json:"actions,omitempty"`
	// Forbid and Require apply to the union of all labels on the call.
	Forbid  []string `json:"forbid,omitempty"`
	Require []string `json:"require,omitempty"`
	// Args holds per-argument rules. Labels under CallLabelsKey count for
	// every argument.
	Args map[string]ArgRule `json:"args,omitempty"`
	// Effect is Escalate (default) or Deny.
	Effect Effect `json:"effect,omitempty"`
	// Tier names the escalation tier. Default "taint".
	Tier      string        `json:"tier,omitempty"`
	Unlabeled UnlabeledMode `json:"unlabeled,omitempty"`
}

// Taint verdicts.
const (
	TaintClean    = "clean"
	TaintEscalate = "escalate"
	TaintDeny     = "deny"
)

// TaintMatch is one violated rule check.
type TaintMatch struct {
	Rule string `json:"rule"`
	// Kind is "forbid" or "require".
	Kind string `json:"kind"`
	// Arg is the argument name, or CallLabelsKey for a call-level check.
	Arg string `json:"arg"`
	// Labels are the offending labels (forbid) or the missing patterns (require).
	Labels []string `json:"labels"`
	Effect Effect   `json:"effect"`
}

// TaintVerdict is the outcome of the taint rules for one request.
type TaintVerdict struct {
	Verdict string       `json:"verdict"`
	Matches []TaintMatch `json:"matches"`
	// Labels is the normalized provenance the verdict was computed from.
	Labels map[string][]string `json:"labels"`
}

// MatchLabel reports whether label matches pattern. "*" matches anything and a
// trailing "*" is a prefix wildcard.
func MatchLabel(pattern, label string) bool {
	if pattern == "*" {
		return true
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(label, p)
	}
	return pattern == label
}

// NormalizeProvenance drops empty labels, dedupes and sorts. It returns nil
// when no label is left.
func NormalizeProvenance(raw map[string][]string) map[string][]string {
	var out map[string][]string
	for arg, labels := range raw {
		clean := make([]string, 0, len(labels))
		for _, l := range labels {
			if l != "" && !slices.Contains(clean, l) {
				clean = append(clean, l)
			}
		}
		if len(clean) == 0 {
			continue
		}
		sort.Strings(clean)
		if out == nil {
			out = map[string][]string{}
		}
		out[arg] = clean
	}
	return out
}

func (r TaintRule) effect() Effect {
	if r.Effect == Deny {
		return Deny
	}
	return Escalate
}

func (r TaintRule) id(i int) string {
	if r.ID != "" {
		return r.ID
	}
	return fmt.Sprint(i)
}

func checkLabels(r TaintRule, id, arg string, labels []string, spec ArgRule, out *[]TaintMatch) {
	eff := r.effect()
	if len(spec.Forbid) > 0 {
		var bad []string
		for _, l := range labels {
			if slices.ContainsFunc(spec.Forbid, func(p string) bool { return MatchLabel(p, l) }) {
				bad = append(bad, l)
			}
		}
		if len(bad) > 0 {
			*out = append(*out, TaintMatch{Rule: id, Kind: "forbid", Arg: arg, Labels: bad, Effect: eff})
		}
	}
	if len(spec.Require) > 0 {
		if len(labels) == 0 && r.Unlabeled != UnlabeledViolate {
			return
		}
		var missing []string
		for _, p := range spec.Require {
			if !slices.ContainsFunc(labels, func(l string) bool { return MatchLabel(p, l) }) {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			*out = append(*out, TaintMatch{Rule: id, Kind: "require", Arg: arg, Labels: missing, Effect: eff})
		}
	}
}

// EvaluateTaint evaluates the Taint rules for req. It returns nil when no
// provenance was supplied and no applicable rule is strict, so a call with no
// labels behaves as before.
func (e Evaluator) EvaluateTaint(req Request) *TaintVerdict {
	prov := NormalizeProvenance(req.Provenance)
	callLabels := prov[CallLabelsKey]
	var all []string
	for _, labels := range prov {
		for _, l := range labels {
			if !slices.Contains(all, l) {
				all = append(all, l)
			}
		}
	}
	sort.Strings(all)

	var matches []TaintMatch
	for i, r := range e.Taint {
		if !Match(r.Resource, req.Resource) {
			continue
		}
		if len(r.Actions) > 0 && !slices.ContainsFunc(r.Actions, func(p string) bool { return Match(p, req.Action) }) {
			continue
		}
		if prov == nil && r.Unlabeled != UnlabeledViolate {
			continue
		}
		id := r.id(i)
		checkLabels(r, id, CallLabelsKey, all, ArgRule{Forbid: r.Forbid, Require: r.Require}, &matches)
		names := make([]string, 0, len(r.Args))
		for n := range r.Args {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			labels := slices.Clone(prov[n])
			for _, l := range callLabels {
				if !slices.Contains(labels, l) {
					labels = append(labels, l)
				}
			}
			sort.Strings(labels)
			checkLabels(r, id, n, labels, r.Args[n], &matches)
		}
	}
	if prov == nil && len(matches) == 0 {
		return nil
	}
	verdict := TaintClean
	if len(matches) > 0 {
		verdict = TaintEscalate
		for _, m := range matches {
			if m.Effect == Deny {
				verdict = TaintDeny
				break
			}
		}
	}
	if prov == nil {
		prov = map[string][]string{}
	}
	return &TaintVerdict{Verdict: verdict, Matches: matches, Labels: prov}
}

func (e Evaluator) taintTier(v *TaintVerdict) string {
	for _, m := range v.Matches {
		if string(m.Effect) != v.Verdict {
			continue
		}
		for i, r := range e.Taint {
			if r.id(i) == m.Rule && r.Tier != "" {
				return r.Tier
			}
		}
		break
	}
	return "taint"
}

func describeTaint(v *TaintVerdict) string {
	parts := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		kind := "forbidden"
		if m.Kind == "require" {
			kind = "missing"
		}
		parts = append(parts, kind+" "+strings.Join(m.Labels, ",")+" on "+m.Arg)
	}
	return "taint: " + strings.Join(parts, "; ")
}

// applyTaint turns an allow into an escalate (or a deny) when a taint rule is
// violated. A deny, and a default deny, pass through. An existing escalate
// stays unless a rule says deny. The verdict is attached as Decision.Taint.
func (e Evaluator) applyTaint(req Request, d Decision) Decision {
	if len(e.Taint) == 0 || (!d.Allowed && d.Effect != Escalate) {
		return d
	}
	v := e.EvaluateTaint(req)
	if v == nil {
		return d
	}
	d.Taint = v
	switch v.Verdict {
	case TaintClean:
		return d
	case TaintDeny:
		d.Allowed, d.Effect, d.Escalation = false, Deny, nil
		d.Reason = "taint violation: " + describeTaint(v)
		return d
	}
	if d.Effect == Escalate {
		return d
	}
	d.Allowed, d.Effect = false, Escalate
	d.Reason = describeTaint(v)
	d.Escalation = &Escalation{Tier: e.taintTier(v), Requirement: RequireApproval, Reason: d.Reason}
	return d
}

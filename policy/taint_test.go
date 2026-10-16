package policy

import "testing"

func TestMatchLabel(t *testing.T) {
	tests := []struct {
		pattern, label string
		want           bool
	}{
		{"*", "anything", true},
		{"tool_output:*", "tool_output:fetch", true},
		{"tool_output:*", "user", false},
		{"user", "user", true},
		{"user", "user2", false},
	}
	for _, tc := range tests {
		if got := MatchLabel(tc.pattern, tc.label); got != tc.want {
			t.Errorf("MatchLabel(%q,%q)=%v", tc.pattern, tc.label, got)
		}
	}
}

func TestEvaluatorTaint(t *testing.T) {
	allow := mustParse(t, `{"version":"1","statements":[{"effect":"allow","actions":["execute"],"resources":["tool:*"]}]}`)
	esc := mustParse(t, `{"version":"1","statements":[{"effect":"escalate","tier":"stmt","actions":["execute"],"resources":["tool:*"]}]}`)
	rule := TaintRule{Resource: "tool:*", Forbid: []string{"bad"}}
	denyRule := TaintRule{Resource: "tool:*", Forbid: []string{"bad"}, Effect: Deny}
	prov := map[string][]string{"a": {"bad"}}
	tests := []struct {
		name    string
		taint   []TaintRule
		pol     *Policy
		prov    map[string][]string
		want    Effect
		verdict string
		tier    string
	}{
		{"no rules", nil, allow, prov, Allow, "", ""},
		{"clean", []TaintRule{rule}, allow, map[string][]string{"a": {"ok"}}, Allow, TaintClean, ""},
		{"escalate", []TaintRule{rule}, allow, prov, Escalate, TaintEscalate, "taint"},
		{"deny", []TaintRule{denyRule}, allow, prov, Deny, TaintDeny, ""},
		{"statement escalate kept", []TaintRule{rule}, esc, prov, Escalate, TaintEscalate, "stmt"},
		{"statement escalate upgraded to deny", []TaintRule{denyRule}, esc, prov, Deny, TaintDeny, ""},
		{"no provenance", []TaintRule{rule}, allow, nil, Allow, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluator{Taint: tc.taint}.Evaluate(Request{Action: "execute", Resource: "tool:x", Provenance: tc.prov}, tc.pol)
			if d.Effect != tc.want || d.Allowed != (tc.want == Allow) {
				t.Fatalf("effect %v allowed %v", d.Effect, d.Allowed)
			}
			if tc.verdict == "" {
				if d.Taint != nil {
					t.Fatalf("taint set: %+v", d.Taint)
				}
			} else if d.Taint == nil || d.Taint.Verdict != tc.verdict {
				t.Fatalf("taint %+v", d.Taint)
			}
			if tc.tier != "" && (d.Escalation == nil || d.Escalation.Tier != tc.tier) {
				t.Fatalf("escalation %+v", d.Escalation)
			}
		})
	}
	// A default deny stays a default deny and carries no verdict.
	d := Evaluator{Taint: []TaintRule{rule}}.Evaluate(Request{Action: "execute", Resource: "tool:x", Provenance: prov})
	if d.Effect == Escalate || d.Taint != nil {
		t.Fatalf("default deny changed: %+v", d)
	}
}

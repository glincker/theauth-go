package policytest_test

import (
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/policytest"
)

const suiteJSON = `{
  "name": "repos",
  "policies": [{"version":"1","id":"p","statements":[
    {"id":"read","effect":"allow","actions":["read"],"resources":["repos/*"]},
    {"id":"office","effect":"allow","actions":["admin"],"resources":["console"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]},
    {"id":"pay","effect":"escalate","actions":["pay"],"resources":["acct/*"]},
    {"id":"nosecret","effect":"deny","actions":["*"],"resources":["repos/secret"]}]}],
  "cases": [
    {"name":"read ok","request":{"action":"read","resource":"repos/a"},"expect":"allowed","code":"allowed"},
    {"name":"write denied","request":{"action":"write","resource":"repos/a"},"expect":"denied","code":"no_permission"},
    {"name":"outside office","request":{"action":"admin","resource":"console","ip":"8.8.8.8"},"expect":"denied","code":"ip_not_allowed"},
    {"name":"pay needs approval","request":{"action":"pay","resource":"acct/1"},"expect":"escalated","code":"approval_required"},
    {"name":"secret denied","request":{"action":"read","resource":"repos/secret"},"expect":"denied"}
  ]}`

func TestLoadSuiteAndRun(t *testing.T) {
	s, err := policytest.LoadSuite(strings.NewReader(suiteJSON))
	if err != nil {
		t.Fatal(err)
	}
	if f := policytest.Run(s); len(f) != 0 {
		t.Fatalf("unexpected failures: %v", f)
	}
	policytest.RunSuite(t, s)
}

func TestRunReportsExplanation(t *testing.T) {
	s, err := policytest.LoadSuite(strings.NewReader(suiteJSON))
	if err != nil {
		t.Fatal(err)
	}
	s.Cases = []policytest.Case{
		policytest.ExpectAllowed("wrong expectation", policytest.Request{Action: "write", Resource: "repos/a"}),
		policytest.ExpectDenied("wrong code", policytest.Request{Action: "read", Resource: "repos/a"}, policy.CodeNoPermission),
		policytest.ExpectDenied("right", policytest.Request{Action: "write", Resource: "repos/a"}, policy.CodeNoPermission),
	}
	fails := policytest.Run(s)
	if len(fails) != 2 {
		t.Fatalf("got %d failures: %v", len(fails), fails)
	}
	msg := fails[0].Error()
	for _, want := range []string{"want allowed, got denied", "near miss", "you hold read on repos/*, this needs write"} {
		if !strings.Contains(msg, want) {
			t.Errorf("failure text missing %q:\n%s", want, msg)
		}
	}
	if fails[1].Got != policytest.Allowed {
		t.Errorf("second failure got %s", fails[1].Got)
	}
}

func TestEvaluatorAndNow(t *testing.T) {
	p, err := policy.Parse([]byte(`{"version":"1","statements":[{"effect":"allow","actions":["pay"],"resources":["acct/*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := policytest.Suite{
		Policies:  []*policy.Policy{p},
		Evaluator: policy.Evaluator{Risk: []policy.RiskTier{{Name: "big", MinAmount: 100, Require: policy.RequireApproval}}},
		Cases: []policytest.Case{
			policytest.ExpectAllowed("small", policytest.Request{Action: "pay", Resource: "acct/1", Amount: 5, Now: time.Now()}),
			policytest.ExpectEscalated("big", policytest.Request{Action: "pay", Resource: "acct/1", Amount: 500}, policy.CodeRiskEscalation),
		},
	}
	policytest.RunSuite(t, s)
}

func TestLoadSuiteRejects(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"unknown field", `{"name":"x","bogus":1}`},
		{"bad outcome", `{"cases":[{"name":"c","request":{"action":"a","resource":"r"},"expect":"maybe"}]}`},
		{"bad code", `{"cases":[{"name":"c","request":{"action":"a","resource":"r"},"expect":"denied","code":"nope"}]}`},
		{"bad policy", `{"policies":[{"version":"9","statements":[]}]}`},
		{"null policy", `{"policies":[null]}`},
		{"not json", `{`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policytest.LoadSuite(strings.NewReader(tc.doc)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

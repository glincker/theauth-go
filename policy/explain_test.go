package policy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExplain(t *testing.T) {
	noon := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	night := time.Date(2026, 10, 5, 23, 30, 0, 0, time.UTC)
	p := pol(t, "p1", `
{"id":"read-repos","effect":"allow","actions":["read"],"resources":["repos/a"]},
{"id":"office-ip","effect":"allow","actions":["admin:*"],"resources":["console/*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]},
{"id":"work-hours","effect":"allow","actions":["report:*"],"resources":["reports/*"],"conditions":[{"op":"daily_window","values":["08:00","18:00"]}]},
{"id":"pay","effect":"escalate","tier":"money","actions":["pay"],"resources":["acct/*"]},
{"id":"no-secrets","effect":"deny","actions":["*"],"resources":["secrets/*"]}`)
	tests := []struct {
		name      string
		req       Request
		allowed   bool
		code      DecisionCode
		matched   string
		condFails int
		miss      string
		missKinds string
	}{
		{"allow", Request{Action: "read", Resource: "repos/a", Now: noon}, true, CodeAllowed, "read-repos", 0, "", ""},
		{"deny by default", Request{Action: "read", Resource: "other/x", Now: noon}, false, CodeNoPermission, "", 0, "read-repos", "resource"},
		{"deny explicit", Request{Action: "read", Resource: "secrets/k", Now: noon}, false, CodeNoPermission, "no-secrets", 0, "", ""},
		{"ip condition fails", Request{Action: "admin:x", Resource: "console/a", IP: "8.8.8.8", Now: noon}, false, CodeIPNotAllowed, "", 1, "office-ip", "condition"},
		{"ip condition holds", Request{Action: "admin:x", Resource: "console/a", IP: "10.1.2.3", Now: noon}, true, CodeAllowed, "office-ip", 0, "", ""},
		{"time condition fails", Request{Action: "report:run", Resource: "reports/q", Now: night}, false, CodeTimeRestricted, "", 1, "work-hours", "condition"},
		{"approval required", Request{Action: "pay", Resource: "acct/1", Now: noon}, false, CodeApprovalRequired, "pay", 0, "", ""},
		{"wrong action on held resource", Request{Action: "write", Resource: "repos/a", Now: noon}, false, CodeNoPermission, "", 0, "read-repos", "action"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			x := Explain(tc.req, p)
			if x.Decision.Allowed != tc.allowed || x.Code != tc.code {
				t.Fatalf("got allowed=%v code=%s, want %v %s\n%s", x.Decision.Allowed, x.Code, tc.allowed, tc.code, x)
			}
			if got := ""; x.Matched != nil {
				got = x.Matched.StatementID
				if got != tc.matched {
					t.Fatalf("matched %q, want %q", got, tc.matched)
				}
			} else if tc.matched != "" {
				t.Fatalf("no match, want %q", tc.matched)
			}
			failed := 0
			for _, c := range x.Conditions {
				if !c.Passed {
					failed++
				}
			}
			if failed != tc.condFails {
				t.Fatalf("failed conditions %d, want %d: %+v", failed, tc.condFails, x.Conditions)
			}
			if tc.miss == "" {
				if len(x.NearMisses) != 0 && x.Matched != nil {
					t.Fatalf("unexpected near misses %+v", x.NearMisses)
				}
				return
			}
			if len(x.NearMisses) == 0 || x.NearMisses[0].StatementID != tc.miss {
				t.Fatalf("near misses %+v, want first %q", x.NearMisses, tc.miss)
			}
			if got := strings.Join(x.NearMisses[0].Mismatch, "+"); got != tc.missKinds {
				t.Fatalf("mismatch %q, want %q", got, tc.missKinds)
			}
		})
	}
}

func TestExplainNearMissRanking(t *testing.T) {
	p := pol(t, "p", `
{"id":"far","effect":"allow","actions":["read"],"resources":["zzz/q"]},
{"id":"wrong-action","effect":"allow","actions":["read"],"resources":["repos/a/files"]},
{"id":"wrong-leaf","effect":"allow","actions":["write"],"resources":["repos/a/other"]},
{"id":"wrong-repo","effect":"allow","actions":["write"],"resources":["repos/b/files"]},
{"id":"deny-ignored","effect":"deny","actions":["write"],"resources":["nope/*"]}`)
	x := Explain(Request{Action: "write", Resource: "repos/a/files"}, p)
	if x.Code != CodeNoPermission {
		t.Fatalf("code %s", x.Code)
	}
	var ids []string
	for _, n := range x.NearMisses {
		ids = append(ids, n.StatementID)
	}
	// wrong-leaf: action ok 0.4 + 0.6*2/3 = 0.8. wrong-action: resource ok,
	// action differs = 0.6. wrong-repo: 0.4 + 0.6*1/3 = 0.6 (tie, policy order).
	want := []string{"wrong-leaf", "wrong-action", "wrong-repo"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("order %v, want %v\n%s", ids, want, x)
	}
	if x.NearMisses[0].Score != 0.8 || x.NearMisses[1].Score != 0.6 {
		t.Fatalf("scores %+v", x.NearMisses)
	}
	if !strings.Contains(x.NearMisses[1].Hint, "you hold read on repos/a/files, this needs write") {
		t.Fatalf("hint %q", x.NearMisses[1].Hint)
	}
}

func TestExplainNearMissCap(t *testing.T) {
	var stmts []string
	for i := range 6 {
		stmts = append(stmts, fmt.Sprintf(`{"id":"s%d","effect":"allow","actions":["read"],"resources":["repos/r%d"]}`, i, i))
	}
	x := Explain(Request{Action: "write", Resource: "repos/zz"}, pol(t, "p", strings.Join(stmts, ",")))
	if len(x.NearMisses) != MaxNearMisses {
		t.Fatalf("got %d near misses", len(x.NearMisses))
	}
}

func TestExplainRiskAndTaintPassThrough(t *testing.T) {
	p := pol(t, "p", `{"id":"a","effect":"allow","actions":["pay"],"resources":["acct/*"]}`)
	e := Evaluator{Risk: []RiskTier{{Name: "big", MinAmount: 100, Require: RequireApproval}}}
	x := e.Explain(Request{Action: "pay", Resource: "acct/1", Amount: 500}, p)
	if x.Code != CodeRiskEscalation || x.Decision.Escalation == nil || x.Matched == nil {
		t.Fatalf("risk explain: %s", x)
	}
}

// corpus builds a deterministic set of cases covering matches, misses,
// conditions, variables, risk and taint.
func corpus(t *testing.T) (Evaluator, []*Policy, []Request) {
	t.Helper()
	pols := []*Policy{
		pol(t, "identity", `
{"id":"r","effect":"allow","actions":["read","list"],"resources":["repos/*"]},
{"effect":"allow","actions":["write"],"resources":["repos/{team}/*"]},
{"id":"net","effect":"allow","actions":["admin:*"],"resources":["console/*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8","2001:db8::/32"]}]},
{"id":"nonet","effect":"allow","actions":["probe"],"resources":["console/*"],"conditions":[{"op":"not_ip_cidr","key":"ip","values":["10.0.0.0/8"]}]},
{"id":"hours","effect":"allow","actions":["report"],"resources":["reports/*"],"conditions":[{"op":"daily_window","values":["22:00","06:00"]}]},
{"id":"abs","effect":"allow","actions":["export"],"resources":["data/*"],"conditions":[{"op":"time_window","values":["2026-10-01T00:00:00Z","2026-10-10T00:00:00Z"]}]},
{"id":"env","effect":"allow","actions":["deploy"],"resources":["svc/*"],"conditions":[{"op":"in","key":"env","values":["stg","dev"]}]},
{"id":"esc","effect":"escalate","tier":"money","actions":["pay"],"resources":["acct/*"]},
{"id":"pay-ok","effect":"allow","actions":["pay"],"resources":["acct/*"]},
{"id":"deny-secret","effect":"deny","actions":["*"],"resources":["repos/secrets","secrets/*"]},
{"effect":"deny","actions":["delete"],"resources":["{missing}"]}`),
		nil,
		pol(t, "second", `{"id":"extra","effect":"allow","actions":["read"],"resources":["docs/*"]}`),
	}
	e := Evaluator{
		Risk:  []RiskTier{{Name: "big", MinAmount: 1000, Require: RequireStepUp}},
		Taint: []TaintRule{{ID: "no-web", Resource: "repos/*", Actions: []string{"write"}, Forbid: []string{"web"}}},
	}
	actions := []string{"read", "write", "admin:x", "probe", "report", "export", "deploy", "pay", "delete", "unknown", ""}
	resources := []string{"repos/a", "repos/a/b", "repos/secrets", "repos/acme/x", "console/main", "reports/q", "data/set", "svc/api", "acct/1", "secrets/k", "docs/x", ""}
	ips := []string{"", "10.2.3.4", "8.8.8.8", "2001:db8::1", "::ffff:10.0.0.1", "not-an-ip"}
	times := []time.Time{
		time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 5, 23, 59, 0, 0, time.UTC),
		time.Date(2026, 10, 11, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
	}
	var reqs []Request
	n := 0
	for ai, a := range actions {
		for ri, r := range resources {
			n++
			req := Request{Action: a, Resource: r, IP: ips[(ai+ri)%len(ips)], Now: times[n%len(times)]}
			if n%3 == 0 {
				req.Attributes = map[string]string{"team": "acme", "env": []string{"dev", "prod"}[n%2]}
			}
			if n%7 == 0 {
				req.Amount = 5000
			}
			if n%5 == 0 {
				req.Provenance = map[string][]string{CallLabelsKey: {"web"}}
			}
			reqs = append(reqs, req)
		}
	}
	aligned := [][2]string{{"read", "repos/a"}, {"write", "repos/acme/x"}, {"admin:x", "console/main"}, {"probe", "console/main"},
		{"report", "reports/q"}, {"export", "data/set"}, {"deploy", "svc/api"}, {"pay", "acct/1"}, {"read", "repos/secrets"}, {"delete", "x"}}
	for i, pair := range aligned {
		for j, ip := range ips {
			reqs = append(reqs, Request{
				Action: pair[0], Resource: pair[1], IP: ip, Now: times[(i+j)%len(times)],
				Attributes: map[string]string{"team": "acme", "env": []string{"dev", "prod"}[j%2]},
			})
		}
	}
	return e, pols, reqs
}

func TestExplainParityWithEvaluate(t *testing.T) {
	e, pols, reqs := corpus(t)
	if len(reqs) < 50 {
		t.Fatalf("corpus too small: %d", len(reqs))
	}
	before := fmt.Sprintf("%+v", pols)
	outcomes := map[DecisionCode]int{}
	for i, req := range reqs {
		want := e.Evaluate(req, pols...)
		got := e.Explain(req, pols...)
		if !reflect.DeepEqual(want, got.Decision) || got.Code != want.Code {
			t.Fatalf("case %d %+v: explain %+v, evaluate %+v", i, req, got.Decision, want)
		}
		if got.String() == "" {
			t.Fatalf("case %d: empty String", i)
		}
		if !want.Allowed && want.Effect == "" && got.Matched != nil {
			t.Fatalf("case %d: default deny reported a match", i)
		}
		if want.Allowed && len(got.NearMisses) != 0 {
			t.Fatalf("case %d: allowed with near misses", i)
		}
		outcomes[want.Code]++
	}
	if after := fmt.Sprintf("%+v", pols); after != before {
		t.Fatal("Explain mutated the policies")
	}
	for _, c := range []DecisionCode{CodeAllowed, CodeNoPermission, CodeIPNotAllowed, CodeTimeRestricted, CodeApprovalRequired} {
		if outcomes[c] == 0 {
			t.Errorf("corpus never produced %s: %v", c, outcomes)
		}
	}
	t.Logf("parity corpus: %d cases, outcomes %v", len(reqs), outcomes)
}

// Explain answers "why": which statement decided, and what almost matched.
func ExampleExplain() {
	p, _ := Parse([]byte(`{"version":"1","id":"repos","statements":[
		{"id":"read-a","effect":"allow","actions":["read"],"resources":["repos/a"]}]}`))
	x := Explain(Request{Action: "write", Resource: "repos/a"}, p)
	fmt.Println(x.Code)
	fmt.Println(x.NearMisses[0].Hint)
	// Output:
	// no_permission
	// you hold read on repos/a, this needs write
}

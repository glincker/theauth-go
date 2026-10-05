package policy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func pol(t *testing.T, id string, stmts string) *Policy {
	t.Helper()
	p := mustParse(t, `{"version":"1","statements":[`+stmts+`]}`)
	p.ID = id
	return p
}

func TestEvaluate(t *testing.T) {
	noon := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	night := time.Date(2026, 10, 5, 23, 30, 0, 0, time.UTC)
	allowDeploy := `{"id":"allow-deploy","effect":"allow","actions":["deploy:*"],"resources":["project/{project_id}","project/{project_id}/*"]}`
	tests := []struct {
		name     string
		policies []*Policy
		req      Request
		allowed  bool
		stmt     string
		reason   string
	}{
		{"default deny with no policies", nil, Request{Action: "deploy:create", Resource: "project/p1"}, false, "", "default deny"},
		{"allow with variable", []*Policy{pol(t, "p", allowDeploy)},
			Request{Action: "deploy:create", Resource: "project/p1", Attributes: map[string]string{"project_id": "p1"}}, true, "allow-deploy", "allowed"},
		{"variable mismatch denies by default", []*Policy{pol(t, "p", allowDeploy)},
			Request{Action: "deploy:create", Resource: "project/p2", Attributes: map[string]string{"project_id": "p1"}}, false, "", "default deny"},
		{"missing variable never allows", []*Policy{pol(t, "p", allowDeploy)},
			Request{Action: "deploy:create", Resource: "project/p1"}, false, "", "default deny"},
		{"star in variable value cannot widen", []*Policy{pol(t, "p", allowDeploy)},
			Request{Action: "deploy:create", Resource: "project/p9", Attributes: map[string]string{"project_id": "*"}}, false, "", "default deny"},
		{"deny beats allow regardless of order", []*Policy{
			pol(t, "a", allowDeploy),
			pol(t, "b", `{"id":"no-prod","effect":"deny","actions":["deploy:*"],"resources":["project/*/env/prod"]}`)},
			Request{Action: "deploy:create", Resource: "project/p1/env/prod", Attributes: map[string]string{"project_id": "p1"}}, false, "no-prod", "explicit deny"},
		{"deny first then allow still denies", []*Policy{
			pol(t, "b", `{"id":"no-prod","effect":"deny","actions":["*"],"resources":["*"]}`),
			pol(t, "a", allowDeploy)},
			Request{Action: "deploy:create", Resource: "project/p1", Attributes: map[string]string{"project_id": "p1"}}, false, "no-prod", "explicit deny"},
		{"deny with unresolved variable fails closed", []*Policy{
			pol(t, "a", `{"effect":"allow","actions":["*"],"resources":["*"]}`),
			pol(t, "b", `{"id":"d","effect":"deny","actions":["*"],"resources":["project/{project_id}"]}`)},
			Request{Action: "x", Resource: "project/other"}, false, "d", "explicit deny"},
		{"unnamed statement gets index id", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"]}`)},
			Request{Action: "x", Resource: "y"}, true, "stmt-0", "allowed"},
		{"action glob does not match other action", []*Policy{pol(t, "p", allowDeploy)},
			Request{Action: "project:delete", Resource: "project/p1", Attributes: map[string]string{"project_id": "p1"}}, false, "", "default deny"},
		{"ip in cidr allows", []*Policy{pol(t, "p", `{"id":"office","effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8","2001:db8::/32"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "10.1.2.3"}, true, "office", "allowed"},
		{"ip v6 in cidr", []*Policy{pol(t, "p", `{"id":"office","effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["2001:db8::/32"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "2001:db8::1"}, true, "office", "allowed"},
		{"ip v4-mapped v6 matches v4 cidr", []*Policy{pol(t, "p", `{"id":"o","effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "::ffff:10.0.0.1"}, true, "o", "allowed"},
		{"ip outside cidr", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "8.8.8.8"}, false, "", "default deny"},
		{"garbage ip never matches cidr", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"ip_cidr","key":"ip","values":["0.0.0.0/0"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "bogus"}, false, "", "default deny"},
		{"deny unless office ip: missing ip denies", []*Policy{
			pol(t, "a", `{"effect":"allow","actions":["*"],"resources":["*"]}`),
			pol(t, "b", `{"id":"office-only","effect":"deny","actions":["*"],"resources":["*"],"conditions":[{"op":"not_ip_cidr","key":"ip","values":["10.0.0.0/8"]}]}`)},
			Request{Action: "x", Resource: "y"}, false, "office-only", "explicit deny"},
		{"equals with variable value", []*Policy{pol(t, "p", `{"id":"own","effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"equals","key":"owner","values":["{principal.id}"]}]}`)},
			Request{Action: "x", Resource: "y", Attributes: map[string]string{"owner": "u1", "principal.id": "u1"}}, true, "own", "allowed"},
		{"equals mismatch", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"equals","key":"owner","values":["u2"]}]}`)},
			Request{Action: "x", Resource: "y", Attributes: map[string]string{"owner": "u1"}}, false, "", "default deny"},
		{"equals on missing key is false", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"equals","key":"owner","values":[""]}]}`)},
			Request{Action: "x", Resource: "y"}, false, "", "default deny"},
		{"in list", []*Policy{pol(t, "p", `{"id":"envs","effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"in","key":"env","values":["stage","prod"]}]}`)},
			Request{Action: "x", Resource: "y", Attributes: map[string]string{"env": "prod"}}, true, "envs", "allowed"},
		{"not_in blocks", []*Policy{
			pol(t, "a", `{"effect":"allow","actions":["*"],"resources":["*"]}`),
			pol(t, "b", `{"id":"nb","effect":"deny","actions":["*"],"resources":["*"],"conditions":[{"op":"not_in","key":"env","values":["dev"]}]}`)},
			Request{Action: "x", Resource: "y", Attributes: map[string]string{"env": "prod"}}, false, "nb", "explicit deny"},
		{"time window inside", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"time_window","values":["2026-10-01T00:00:00Z","2026-11-01T00:00:00Z"]}]}`)},
			Request{Action: "x", Resource: "y", Now: noon}, true, "stmt-0", "allowed"},
		{"time window end exclusive", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"time_window","values":["","2026-10-05T12:00:00Z"]}]}`)},
			Request{Action: "x", Resource: "y", Now: noon}, false, "", "default deny"},
		{"time window before start", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"time_window","values":["2026-10-06T00:00:00Z",""]}]}`)},
			Request{Action: "x", Resource: "y", Now: noon}, false, "", "default deny"},
		{"daily window business hours", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"daily_window","values":["09:00","17:00"]}]}`)},
			Request{Action: "x", Resource: "y", Now: noon}, true, "stmt-0", "allowed"},
		{"daily window outside", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"daily_window","values":["09:00","17:00"]}]}`)},
			Request{Action: "x", Resource: "y", Now: night}, false, "", "default deny"},
		{"daily window wraps midnight", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"daily_window","values":["22:00","06:00"]}]}`)},
			Request{Action: "x", Resource: "y", Now: night}, true, "stmt-0", "allowed"},
		{"all conditions must hold", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"in","key":"env","values":["prod"]},{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]}`)},
			Request{Action: "x", Resource: "y", IP: "8.8.8.8", Attributes: map[string]string{"env": "prod"}}, false, "", "default deny"},
		{"literal braces stay literal", []*Policy{pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["a{b c}d","x{}y"]}`)},
			Request{Action: "x", Resource: "x{}y"}, true, "stmt-0", "allowed"},
		{"nil policy ignored", []*Policy{nil}, Request{Action: "x", Resource: "y"}, false, "", "default deny"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluator{}.Evaluate(tc.req, tc.policies...)
			if d.Allowed != tc.allowed || d.StatementID != tc.stmt || !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("decision = %+v, want allowed=%v stmt=%q reason~%q", d, tc.allowed, tc.stmt, tc.reason)
			}
		})
	}
}

func TestEvaluatorClock(t *testing.T) {
	p := pol(t, "p", `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":[{"op":"daily_window","values":["09:00","10:00"]}]}`)
	in := Evaluator{Now: func() time.Time { return time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC) }}
	if !in.Evaluate(Request{Action: "a", Resource: "b"}, p).Allowed {
		t.Fatal("injected clock inside window should allow")
	}
}

func TestBoundaryNeverWidens(t *testing.T) {
	identity := []*Policy{pol(t, "user", `{"effect":"allow","actions":["deploy:*","project:read"],"resources":["*"]}`)}
	boundary := []*Policy{pol(t, "tok", `{"id":"read-only","effect":"allow","actions":["project:read"],"resources":["*"]}`)}
	tests := []struct {
		name     string
		action   string
		identity []*Policy
		boundary []*Policy
		allowed  bool
		boundOK  bool
	}{
		{"within both", "project:read", identity, boundary, true, false},
		{"owner allows, boundary narrows", "deploy:create", identity, boundary, false, true},
		{"boundary allows, owner does not", "project:read", nil, boundary, false, false},
		{"no boundary leaves owner perms", "deploy:create", identity, nil, true, false},
		{"boundary explicit deny", "project:read", identity, append([]*Policy{pol(t, "d", `{"effect":"deny","actions":["project:*"],"resources":["*"]}`)}, boundary...), false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluator{}.EvaluateWithBoundary(Request{Action: tc.action, Resource: "r"}, tc.identity, tc.boundary)
			if d.Allowed != tc.allowed || d.Boundary != tc.boundOK {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
}

func TestEvaluateConcurrent(t *testing.T) {
	p := pol(t, "p", `{"id":"a","effect":"allow","actions":["deploy:*"],"resources":["project/{project_id}"]},
	  {"id":"d","effect":"deny","actions":["*"],"resources":["project/locked"]}`)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := fmt.Sprintf("p%d", (g+i)%7)
				d := Evaluator{}.Evaluate(Request{Action: "deploy:x", Resource: "project/" + id, Attributes: map[string]string{"project_id": id}}, p)
				if !d.Allowed {
					errs <- fmt.Errorf("want allow for %s: %+v", id, d)
					return
				}
				if d := (Evaluator{}).Evaluate(Request{Action: "deploy:x", Resource: "project/locked", Attributes: map[string]string{"project_id": "locked"}}, p); d.Allowed {
					errs <- fmt.Errorf("locked allowed: %+v", d)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

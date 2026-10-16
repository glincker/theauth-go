package policy

import (
	"testing"
	"time"
)

// BenchmarkAuthorize measures one Evaluate call over a realistic mix: an
// allow with a variable-bound resource, an unrelated deny, a condition, and
// a risk tier that escalates the result. Allocations per op are the number
// to watch when touching the hot path.
func BenchmarkAuthorize(b *testing.B) {
	allow := mustParseB(b, `{"version":"1","statements":[
		{"id":"allow-deploy","effect":"allow","actions":["deploy:*","read:*"],
		 "resources":["project/{project_id}","project/{project_id}/*"],
		 "conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]}]},
		{"effect":"allow","actions":["project:list"],"resources":["org/*"]}]}`)
	deny := mustParseB(b, `{"version":"1","statements":[
		{"id":"no-prod","effect":"deny","actions":["deploy:*"],"resources":["project/*/env/prod"]}]}`)
	risk := []RiskTier{{Name: "high", MinAmount: 1000, Currency: "USD", Require: RequireStepUp}}
	ev := Evaluator{Risk: risk, Now: func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }}
	req := Request{
		Action:     "deploy:create",
		Resource:   "project/p1/env/staging",
		Attributes: map[string]string{"project_id": "p1"},
		IP:         "10.1.2.3",
		Amount:     10,
		Currency:   "USD",
	}
	policies := []*Policy{allow, deny}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := ev.Evaluate(req, policies...); !d.Allowed {
			b.Fatalf("expected allow, got %+v", d)
		}
	}
}

// BenchmarkAuthorizeDefaultDeny measures the no-match path, which walks every
// statement and returns the default-deny decision.
func BenchmarkAuthorizeDefaultDeny(b *testing.B) {
	p := mustParseB(b, `{"version":"1","statements":[
		{"effect":"allow","actions":["a:*"],"resources":["x/*"]},
		{"effect":"allow","actions":["b:*"],"resources":["y/*"]},
		{"effect":"allow","actions":["c:*"],"resources":["z/*"]}]}`)
	req := Request{Action: "d:none", Resource: "q/1"}
	var ev Evaluator

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := ev.Evaluate(req, p); d.Allowed {
			b.Fatal("expected default deny")
		}
	}
}

func mustParseB(b *testing.B, doc string) *Policy {
	b.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	return p
}

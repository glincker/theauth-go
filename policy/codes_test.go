package policy

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDecisionCodeEvaluation(t *testing.T) {
	t.Parallel()
	noon := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	allow := `{"effect":"allow","actions":["a"],"resources":["*"]}`
	tests := []struct {
		name string
		ev   Evaluator
		pols []*Policy
		req  Request
		want DecisionCode
	}{
		{"allow", Evaluator{}, []*Policy{pol(t, "p", allow)}, Request{Action: "a", Resource: "r"}, CodeAllowed},
		{"explicit deny", Evaluator{}, []*Policy{pol(t, "p", allow+`,{"effect":"deny","actions":["a"],"resources":["*"]}`)}, Request{Action: "a", Resource: "r"}, CodeNoPermission},
		{"no policies", Evaluator{}, nil, Request{Action: "a", Resource: "r"}, CodeNoPermission},
		{"no matching statement", Evaluator{}, []*Policy{pol(t, "p", allow)}, Request{Action: "b", Resource: "r"}, CodeNoPermission},
		{"escalate statement", Evaluator{}, []*Policy{pol(t, "p", `{"effect":"escalate","actions":["a"],"resources":["*"]}`)}, Request{Action: "a", Resource: "r"}, CodeApprovalRequired},
		{"ip condition fails", Evaluator{}, []*Policy{pol(t, "p", `{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"key":"ip","op":"ip_cidr","values":["10.0.0.0/8"]}]}`)}, Request{Action: "a", Resource: "r", IP: "8.8.8.8"}, CodeIPNotAllowed},
		{"daily window fails", Evaluator{Now: func() time.Time { return noon }}, []*Policy{pol(t, "p", `{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"daily_window","values":["22:00","23:00"]}]}`)}, Request{Action: "a", Resource: "r"}, CodeTimeRestricted},
		{"risk tier", Evaluator{Risk: []RiskTier{{Name: "big", MinAmount: 10, Require: RequireApproval}}}, []*Policy{pol(t, "p", allow)}, Request{Action: "a", Resource: "r", Amount: 50}, CodeRiskEscalation},
		{"taint deny", Evaluator{Taint: []TaintRule{{Resource: "*", Forbid: []string{"untrusted"}, Effect: TaintDeny}}}, []*Policy{pol(t, "p", allow)}, Request{Action: "a", Resource: "r", Provenance: map[string][]string{CallLabelsKey: {"untrusted"}}}, CodeTaintViolation},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := tc.ev.Evaluate(tc.req, tc.pols...)
			if d.Code != tc.want {
				t.Fatalf("code = %q, want %q (reason %q)", d.Code, tc.want, d.Reason)
			}
			if !d.Code.Valid() {
				t.Fatalf("code %q is not a defined code", d.Code)
			}
		})
	}
}

func TestDecisionCodeBoundary(t *testing.T) {
	t.Parallel()
	identity := []*Policy{pol(t, "i", `{"effect":"allow","actions":["a"],"resources":["*"]}`)}
	boundary := []*Policy{pol(t, "b", `{"effect":"allow","actions":["other"],"resources":["*"]}`)}
	d := Evaluator{}.EvaluateWithBoundary(Request{Action: "a", Resource: "r"}, identity, boundary)
	if d.Allowed || d.Code != CodeNoPermission || !d.Boundary {
		t.Fatalf("got %+v", d)
	}
	d = Evaluator{}.EvaluateWithBoundary(Request{Action: "a", Resource: "r"}, identity, nil)
	if d.Code != CodeAllowed {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionJSONIncludesCode(t *testing.T) {
	t.Parallel()
	d := Evaluator{}.Evaluate(Request{Action: "a", Resource: "r"})
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["code"] != "no_permission" {
		t.Fatalf("json = %s", raw)
	}
}

func TestDecisionCodeSetHasUniqueValues(t *testing.T) {
	t.Parallel()
	seen := map[DecisionCode]bool{}
	for _, c := range AllDecisionCodes() {
		if c == "" || seen[c] || strings.ToLower(string(c)) != string(c) {
			t.Fatalf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 28 {
		t.Fatalf("got %d codes, TypeScript defines 28", len(seen))
	}
}

// TestDecisionCodesDocumented parses the docs table and requires a row for
// every defined code and no row for an unknown one. It also requires that
// every exported Code constant in codes.go is listed by AllDecisionCodes.
func TestDecisionCodesDocumented(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile("../docs/agent-policies.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	start := strings.Index(text, "## Decision codes")
	if start < 0 {
		t.Fatal("docs/agent-policies.md has no Decision codes section")
	}
	text = text[start+len("## Decision codes"):]
	if end := strings.Index(text, "\n## "); end >= 0 {
		text = text[:end]
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")
	documented := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(text, -1) {
		documented[m[1]] = true
	}
	for _, c := range AllDecisionCodes() {
		if !documented[string(c)] {
			t.Errorf("code %q has no row in docs/agent-policies.md", c)
		}
		delete(documented, string(c))
	}
	for extra := range documented {
		t.Errorf("docs row %q is not a defined code", extra)
	}

	src, err := os.ReadFile("codes.go")
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^\s+(Code[A-Za-z]+)\s+DecisionCode = "([a-z_]+)"`)
	consts := decl.FindAllStringSubmatch(string(src), -1)
	if len(consts) != len(AllDecisionCodes()) {
		t.Fatalf("codes.go declares %d constants, AllDecisionCodes lists %d", len(consts), len(AllDecisionCodes()))
	}
	for _, m := range consts {
		if !DecisionCode(m[2]).Valid() {
			t.Errorf("constant %s (%q) missing from AllDecisionCodes", m[1], m[2])
		}
	}
}

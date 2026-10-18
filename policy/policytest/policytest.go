// Package policytest is a small declarative test kit for policy documents.
// A Suite holds policies and cases; each case is a request plus the expected
// outcome. Failures print the policy.Explanation, so a failing case shows
// the matched statement, failed conditions and near misses.
//
// Suites are built in Go with ExpectAllowed, ExpectDenied and
// ExpectEscalated, or loaded from JSON with LoadSuite. It imports only the
// public policy package and never touches the clock, storage or audit.
package policytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
)

// Outcome is the expected result of a case.
type Outcome string

// Outcomes.
const (
	Allowed   Outcome = "allowed"
	Denied    Outcome = "denied"
	Escalated Outcome = "escalated"
)

// Request is the JSON friendly form of policy.Request.
type Request struct {
	Action       string              `json:"action"`
	Resource     string              `json:"resource"`
	Attributes   map[string]string   `json:"attributes,omitempty"`
	IP           string              `json:"ip,omitempty"`
	Now          time.Time           `json:"now,omitempty"`
	Amount       float64             `json:"amount,omitempty"`
	Currency     string              `json:"currency,omitempty"`
	DataClass    string              `json:"dataClass,omitempty"`
	Irreversible bool                `json:"irreversible,omitempty"`
	Provenance   map[string][]string `json:"provenance,omitempty"`
}

func (r Request) toPolicy() policy.Request {
	return policy.Request{
		Action: r.Action, Resource: r.Resource, Attributes: r.Attributes, IP: r.IP, Now: r.Now,
		Amount: r.Amount, Currency: r.Currency, DataClass: r.DataClass,
		Irreversible: r.Irreversible, Provenance: r.Provenance,
	}
}

// Case is one request and its expected outcome.
type Case struct {
	Name    string  `json:"name"`
	Request Request `json:"request"`
	Expect  Outcome `json:"expect"`
	// Code, when set, must equal the decision code. Empty accepts any code.
	Code policy.DecisionCode `json:"code,omitempty"`
}

// Suite is a named set of cases over one set of policies.
type Suite struct {
	Name     string           `json:"name"`
	Policies []*policy.Policy `json:"policies"`
	Cases    []Case           `json:"cases"`
	// Evaluator carries risk tiers and taint rules. Not part of the JSON form.
	Evaluator policy.Evaluator `json:"-"`
}

// Failure is one case that did not meet its expectation.
type Failure struct {
	Case        Case
	Got         Outcome
	Explanation policy.Explanation
}

// Error describes the failure, including the explanation.
func (f Failure) Error() string {
	want := string(f.Case.Expect)
	if f.Case.Code != "" {
		want += " with code " + string(f.Case.Code)
	}
	return fmt.Sprintf("case %q: want %s, got %s\n%s", f.Case.Name, want, f.Got, f.Explanation)
}

// ExpectAllowed builds a case that must be allowed.
func ExpectAllowed(name string, req Request) Case {
	return Case{Name: name, Request: req, Expect: Allowed}
}

// ExpectDenied builds a case that must be denied with the given code. An
// empty code accepts any denial.
func ExpectDenied(name string, req Request, code policy.DecisionCode) Case {
	return Case{Name: name, Request: req, Expect: Denied, Code: code}
}

// ExpectEscalated builds a case that must need approval or step up.
func ExpectEscalated(name string, req Request, code policy.DecisionCode) Case {
	return Case{Name: name, Request: req, Expect: Escalated, Code: code}
}

// Run evaluates every case and returns the failures. It has no dependency
// on testing, so tools can use it directly.
func Run(s Suite) []Failure {
	var out []Failure
	for _, c := range s.Cases {
		if f, ok := check(s, c); !ok {
			out = append(out, f)
		}
	}
	return out
}

func check(s Suite, c Case) (Failure, bool) {
	x := s.Evaluator.Explain(c.Request.toPolicy(), s.Policies...)
	got := Denied
	switch {
	case x.Decision.Allowed:
		got = Allowed
	case x.Decision.Effect == policy.Escalate:
		got = Escalated
	}
	ok := got == c.Expect && (c.Code == "" || c.Code == x.Code)
	return Failure{Case: c, Got: got, Explanation: x}, ok
}

// RunSuite runs each case as a subtest and fails it with the explanation.
func RunSuite(t *testing.T, s Suite) {
	t.Helper()
	for _, c := range s.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if f, ok := check(s, c); !ok {
				t.Error(f.Error())
			}
		})
	}
}

// LoadSuite decodes a JSON suite. Unknown fields, bad policies and unknown
// outcomes are errors.
func LoadSuite(r io.Reader) (Suite, error) {
	raw, err := io.ReadAll(io.LimitReader(r, policy.MaxDocumentBytes+1))
	if err != nil {
		return Suite{}, fmt.Errorf("policytest: read suite: %w", err)
	}
	if len(raw) > policy.MaxDocumentBytes {
		return Suite{}, errors.New("policytest: suite too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Suite
	if err := dec.Decode(&s); err != nil {
		return Suite{}, fmt.Errorf("policytest: decode suite: %w", err)
	}
	for i, p := range s.Policies {
		if p == nil {
			return Suite{}, fmt.Errorf("policytest: policy %d is null", i)
		}
		if err := p.Validate(); err != nil {
			return Suite{}, fmt.Errorf("policytest: policy %d: %w", i, err)
		}
	}
	for _, c := range s.Cases {
		switch c.Expect {
		case Allowed, Denied, Escalated:
		default:
			return Suite{}, fmt.Errorf("policytest: case %q: expect must be allowed, denied or escalated, got %q", c.Name, c.Expect)
		}
		if c.Code != "" && !c.Code.Valid() {
			return Suite{}, fmt.Errorf("policytest: case %q: unknown code %q", c.Name, c.Code)
		}
	}
	return s, nil
}

// LoadSuiteFile reads a JSON suite from path.
func LoadSuiteFile(path string) (Suite, error) {
	f, err := os.Open(path)
	if err != nil {
		return Suite{}, fmt.Errorf("policytest: open suite: %w", err)
	}
	defer func() { _ = f.Close() }()
	return LoadSuite(f)
}

package policytest_test

import (
	"fmt"
	"strings"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/policy/policytest"
)

// A suite in Go. In a real test, call policytest.RunSuite(t, suite).
func ExampleRun() {
	p, _ := policy.Parse([]byte(`{"version":"1","id":"repos","statements":[
		{"id":"read","effect":"allow","actions":["read"],"resources":["repos/a"]}]}`))
	suite := policytest.Suite{
		Policies: []*policy.Policy{p},
		Cases: []policytest.Case{
			policytest.ExpectAllowed("read a", policytest.Request{Action: "read", Resource: "repos/a"}),
			policytest.ExpectDenied("write a", policytest.Request{Action: "write", Resource: "repos/a"}, policy.CodeNoPermission),
			policytest.ExpectAllowed("write a is wrongly expected", policytest.Request{Action: "write", Resource: "repos/a"}),
		},
	}
	for _, f := range policytest.Run(suite) {
		fmt.Println(f.Error())
	}
	// Output:
	// case "write a is wrongly expected": want allowed, got denied
	// denied (no_permission): no matching allow statement (default deny)
	//   near miss "read" (0.60, action): you hold read on repos/a, this needs write
}

// Suites also load from JSON, which the CLI uses.
func ExampleLoadSuite() {
	s, err := policytest.LoadSuite(strings.NewReader(`{
		"policies": [{"version":"1","statements":[{"effect":"allow","actions":["read"],"resources":["docs/*"]}]}],
		"cases": [{"name":"read docs","request":{"action":"read","resource":"docs/x"},"expect":"allowed"}]}`))
	fmt.Println(err, len(s.Cases), len(policytest.Run(s)))
	// Output: <nil> 1 0
}

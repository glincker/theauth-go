# Policy explain and testing

`policy.Explain` answers "why" for a policy decision, and `policy/policytest` turns those answers into tests. Both are read only: no audit rows, no counters, no approvals spent.

## Explain

```go
x := policy.Explain(policy.Request{Action: "write", Resource: "repos/a"}, p)
fmt.Println(x.Code)                // no_permission
fmt.Println(x.NearMisses[0].Hint)  // you hold read on repos/a, this needs write
```

`Evaluator.Explain` does the same for an evaluator that has risk tiers or taint rules. The result, `policy.Explanation`, holds:

| Field | Meaning |
|---|---|
| `Decision`, `Code` | Exactly what `Evaluate` returns. `Explain` calls `Evaluate` itself, so the two cannot drift, and a parity test checks a corpus of generated cases (edge cases, conditions, risk and taint included). |
| `Matched` | Policy id, statement id and effect of the statement that decided. Nil on a default deny. |
| `Conditions` | For a matched statement, every condition it checked (all passed). For a default deny, the conditions that failed on statements covering the action and resource, for example a source IP outside the allowlist or a closed time window. |
| `NearMisses` | Only on a default deny: up to 3 allow or escalate statements that almost matched, best first. |

Risk tier escalations and taint verdicts stay on `Decision` (`Escalation`, `Taint`).

### Near misses

Each near miss has a `Mismatch` list (`resource`, `action`, `condition`), a human `Hint` and a `Score` in 0..1. The score is `0.6 * resource overlap + 0.4 if the action matched`, where overlap is the share of leading `/` segments the resource pattern covers (using the evaluator's own glob match per segment). A statement that covers the action and resource and fails only on a condition scores 0.9. Statements with no shared segment and no action match are not reported. Explicit denies are never near misses, and an explicit deny is reported as the match instead.

## Testing policies

`policytest` is a public package that depends only on `policy`:

```go
func TestRepoPolicy(t *testing.T) {
    p, _ := policy.Parse(doc)
    policytest.RunSuite(t, policytest.Suite{
        Policies: []*policy.Policy{p},
        Cases: []policytest.Case{
            policytest.ExpectAllowed("read a", policytest.Request{Action: "read", Resource: "repos/a"}),
            policytest.ExpectDenied("write a", policytest.Request{Action: "write", Resource: "repos/a"}, policy.CodeNoPermission),
            policytest.ExpectEscalated("pay", policytest.Request{Action: "pay", Resource: "acct/1"}, policy.CodeApprovalRequired),
        },
    })
}
```

Each case is a subtest. A failure prints the `Explanation`, so you see the matched statement, failed conditions and near misses. An empty code in `ExpectDenied` accepts any denial. Set `Suite.Evaluator` to test risk tiers and taint rules. `policytest.Run(suite)` returns the failures without `testing`.

Suites also load from JSON (`LoadSuite`, `LoadSuiteFile`):

```json
{
  "policies": [{"version": "1", "statements": [
    {"effect": "allow", "actions": ["read"], "resources": ["docs/*"]}]}],
  "cases": [
    {"name": "read docs", "request": {"action": "read", "resource": "docs/x"}, "expect": "allowed"},
    {"name": "write docs", "request": {"action": "write", "resource": "docs/x"}, "expect": "denied", "code": "no_permission"}
  ]
}
```

Run it from the command line with `theauth-go policy test suite.json`. It prints failing cases with their explanation and exits 1 when any case fails (2 for a bad file).

# Policy shrink

Agents tend to be granted more than they need, because widening a grant is easier than working out the narrow one. `policy/shrink` goes the other way. It reads the authorization decisions recorded for an agent over a window, finds the grants that were never used, proposes a smaller permission set and replays the recorded decisions against it to show what would flip.

Nothing is changed for you. Every function reads data and returns a report. You decide whether to apply it.

## How it works

1. `AnalyzeUsage` loads the agent's grants (allow statements of its policies, plus active, unexpired delegation grants), splits them to one action each, reads the decision rows in pages, and attributes every allowed call to the first grant that matches it. Matching is `policy.Match`, the policy engine's own glob.
2. `SuggestShrink` turns the analysis into `Keep`, `Remove` and `Rewrites`. It is pure and deterministic.
3. `VerifyShrink` replays rows against a proposal. `PreviewPolicyChange` does the same by reading the rows itself, and works for any change, including a widening.

Only allowed rows count as use. A call denied for another cause (explicit deny, rate limit, escalation, revoked agent) is not proof a grant is idle. If such a call matched a grant, that grant lands in `AttemptedOnly` and stays in `Keep`. A denial counts as "no grant" only when its reason is the default deny ("no matching allow statement ...").

## Run it

```go
grants := shrink.StorageGrants{Policies: loadPolicies, Delegations: store}
rows := shrink.AuditRows{Store: store}

since := time.Now().AddDate(0, 0, -30)
analysis, err := shrink.AnalyzeUsage(ctx, grants, rows, agentID, shrink.AnalyzeOptions{Since: since})
plan := shrink.SuggestShrink(analysis, shrink.Options{MinObservations: 5})
report, err := shrink.PreviewPolicyChange(ctx, rows, agentID, plan.Keep, shrink.PreviewOptions{
	Since: since,
})
fmt.Println(plan.Remove, report.NewlyDenied)

next := policy.Policy{Version: policy.Version, Statements: shrink.Statements(plan.Keep)}
```

`loadPolicies` has the shape of `toolguard.PoliciesFunc`, so the function your guard uses can be reused. Both interfaces are small (`GrantSource`, `RowSource`), so a test or an export file can stand in for the store: see `StaticGrants` and `MemoryRows`.

## Recording decisions

`AuditRows` reads `agent.authorize` audit events whose `ActorID` is the agent. The authorized action, resource, result and reason live in metadata. Build the event with `shrink.DecisionEvent` and map a decision with `shrink.ResultOf`. The simplest writer is a `toolguard.Guard.OnDecision` hook; see `examples/policy-shrink`.

Rows are read with the store's own cursor, one page at a time (default 1000, `PageSize` to change it). The audit store pages newest first and has no actor filter, so rows are filtered after each read. Memory is bounded by the page size plus the distinct pairs seen (capped at `DistinctCap`).

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `MinObservations` | 1 | Allowed calls a permission needs to be kept. |
| `Generalize` | false | Merge observed sibling resources into `parent:*`. |
| `GeneralizeMin` | 3 | Distinct observed siblings needed before a merge. |

With `Generalize`, `mcp:github:issues`, `mcp:github:pulls` and `mcp:github:repos` can become `mcp:github:*`. A merge happens only when every merged resource was used, an existing grant already covers the wildcard (so the result is never wider than today), and the wildcard matches no call that was denied for lack of a grant. The wildcard still admits siblings nobody has called yet, so each merge is listed in `Rewrites`. Leave it off if you want the result to match observed use exactly.

## Reading the report

| Field | Meaning |
| --- | --- |
| `ReplayedAllows`, `StillAllowed` | Historical allowed calls, and how many the proposal still allows. |
| `NewlyDeniedCount`, `NewlyDenied` | Allowed calls the proposal would deny. The count is exact, the list is capped at `MaxExamples` (default 1000). |
| `WouldAlsoAllowCount`, `WouldAlsoAllow` | Calls denied for lack of a grant that the proposal would allow. Expect entries when you widen. |
| `IgnoredRows` | Bookkeeping rows and denials for other causes. |
| `PerPermission` | Allows attributed to each proposed permission. |

Allowed calls that no current grant covers (an expired delegation, a removed statement) are listed in `analysis.Uncovered`; a set built from today's grants cannot reproduce them.

## Limits

- It proves past behaviour only. A rare legitimate call (a quarterly job) can fall outside the window and be proposed for removal. Review `Remove` and widen `Since` for agents with long cycles.
- Matching covers action and resource. Conditions (time windows, CIDRs, risk tiers) depend on live state, so they are carried over on kept permissions but not re-evaluated.
- Only allow statements are grants. Deny and escalate statements are not touched; keep them in the policy when you apply a suggestion.
- `{var}` placeholders in resource patterns are matched literally, not expanded.
- Overlapping grants are attributed first match wins, in policy order. A broad grant listed before a narrow one gets the credit and the narrow one shows as unused.
- Reading is bounded by audit retention, and rows only exist for decisions that were recorded.

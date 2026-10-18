# Agent policies and rate limits

Attach an IAM policy to an agent and the library enforces it when a token is minted. A rule such as "this agent may never delete" is then an explicit `deny` statement the token endpoint checks, not a sentence in a prompt the model can be talked out of.

Two optional fields on `AgentConfig` do the work. With neither set, minting behaves exactly as before.

```go
engine, err := agentpolicy.New(agentpolicy.Config{
    // Applies to every agent.
    Policies: []policy.Policy{autonomyDenylist},
    // Deny list: only Deny and Escalate restrict. The default is AllowList.
    Mode: agentpolicy.DenyList,
    // Per agent policies and an optional per agent rate limit, from your IAM store.
    ResolverV2: func(ctx context.Context, ag theauth.Agent) (agentpolicy.Resolution, error) {
        p, limit, err := iam.ForAgent(ctx, ag.ID.String())
        return agentpolicy.Resolution{Policies: p, RateLimit: limit}, err
    },
})

AgentIdentity: &theauth.AgentConfig{
    PolicyEngine: engine,
    RateLimit:    theauth.AgentRateLimit{Requests: 60, Per: time.Minute, Burst: 10},
},
```

The `agentpolicy` package is separate from the root package because policy documents live in `policy`, which imports the root.

## The autonomy denylist as an IAM Deny

```go
autonomyDenylist := policy.Policy{
    Version: policy.Version,
    ID:      "autonomy-denylist-v3",
    Statements: []policy.Statement{{
        ID:        "no-irreversible-actions",
        Effect:    policy.Deny,
        Actions:   []string{"payments.refund", "records.delete", "users.suspend"},
        Resources: []string{"*"},
    }},
}
```

An agent holding this policy cannot get a token that carries `payments.refund`, whatever its registered scopes or delegation grant say. Deny always wins over allow. This set has no allow statement, so run it with `Mode: agentpolicy.DenyList`; the default AllowList mode rejects it on purpose.

## Allow list and deny list

`agentpolicy.Config.Mode` says what happens to an action no statement matches. You choose it; there is no implicit switch.

- **`AllowList` (the default).** Nothing passes unless an `allow` statement covers it. A policy set with no `allow` statement is an error, not an open door: `agentpolicy.New` returns `ErrNoAllowStatement` when static `Policies` have no allow and there is no resolver, and a mint whose resolved set has no allow fails closed with the same error (`503 temporarily_unavailable`, `error_class=no_allow_statement` in the audit event).
- **`DenyList`.** Only `deny` and `escalate` statements restrict; an unmatched action passes. Use it for a denylist such as the autonomy rules above. It never widens access: the caps in the next section still apply.

## How a mint is evaluated

Every scope the token would carry is an action, and the token audience is the resource. Policy runs after the grant's own narrowing, so it can only remove scopes.

| Situation | Result |
| --- | --- |
| No policy attached to the agent | Unchanged. |
| A scope you asked for by name hits a `deny` or `escalate` statement | `400 access_denied`, naming the action. |
| A scope you asked for by name matches no `allow` statement (AllowList mode) | `400 invalid_scope`. |
| No scope was requested, so the default set is issued | Denied and (in AllowList mode) unmatched scopes are dropped. If none are left, `access_denied`. |
| The resolver errors, returns an invalid document or an invalid rate limit, or AllowList finds no allow statement | `503 temporarily_unavailable` with `Retry-After`. Fails closed. |

An `escalate` statement needs a human, which a token endpoint cannot ask, so it counts as a refusal at mint time. Use `policy/toolguard` for approval flows at call time. The error text names the denied action and never the policy id, statement id or document; those go to the audit log.

### What caps a grant

These caps hold in both modes, because policy runs last and only removes scopes.

| Grant | Capped by (before policy runs) |
| --- | --- |
| `client_credentials` | The agent's client registered scopes (or the agent's scopes when the client has none), and the resource's scope catalog. The agent's owner is not modeled as a scope cap here. |
| Token exchange (RFC 8693) | The subject (user) token's scopes, the delegation grant's scopes (the user's grant to this agent), the resource catalog, and the grant and token lifetimes. |
| `jwt-bearer` for an agent client | The agent's registered scopes, applied only when an engine is configured and a policy applies. A plain `jwt-bearer` mint with no policy keeps its existing behavior. |

A request for a scope above a cap is `invalid_scope` whether or not policy would have allowed it.

## Resolver errors and the outage guarantee

A resolver error, an invalid policy document, an invalid per agent rate limit or an AllowList set with no allow fails the mint closed. The cause is never shown to the client. It is made visible to you instead:

- Audit event `agent.policy_resolver_failed` with `agent_id`, `client_id`, `grant` and `error_class` (`resolver_error`, `invalid_policy`, `invalid_rate_limit` or `no_allow_statement`). The raw error text is not recorded, because it can carry secrets.
- Counter `theauth_agent_policy_resolver_errors_total`, labelled by grant type (`theauth.MetricAgentPolicyResolverErrors`, through `Config.Observability`).

The resolver runs only inside agent OAuth token mints (`client_credentials`, token exchange, `jwt-bearer` for an agent client) and `AuthorizeAgent`. Sessions, human login, session links and API tokens never call it, so a resolver outage cannot lock people out; the tests make the resolver fail and check a session login, session validation and an API token check on the same instance. The resolver is called on every agent mint, so keep it fast or cache it.

## Accountability

The policies in force are recorded, so a token can be tied to the exact rules that vetted it:

- The access token carries an `agent_policy` claim: `{"ids": ["autonomy-denylist-v3"], "hash": "<sha-256 of the policy documents>"}`. It is absent when no policy applied.
- `agent.token_minted` and `token.exchanged` audit events carry the same `agent_policy` object, plus `policy_dropped_scopes` when a default mint was narrowed.
- A refused mint emits `agent.token_denied` with the action, the effect, `policy_id`, `statement_id` and `agent_policy`.

Give each policy document a stable `id` and change it when the text changes; the hash covers the case where it is not.

## Checking at call time

A resource server that holds an agent id can ask the same question the token endpoint asks:

```go
if err := auth.AuthorizeAgent(ctx, agentID, "payments.refund", "acct/9"); err != nil {
    var denied *theauth.AgentPolicyDeniedError
    var limited *theauth.AgentRateLimitedError
    switch {
    case errors.As(err, &denied): // forbidden
    case errors.As(err, &limited): // retry after limited.RetryAfter
    default: // could not decide, treat as forbidden
    }
}
```

An unknown, suspended or malformed agent id fails closed. To use `policy/toolguard` instead, point the guard at the same engine and budget:

```go
guard := &toolguard.Guard{
    Policies: engine.Policies(auth), // the same policies the token endpoint used
    Limit:    auth.CheckAgentRate,   // the same per agent budget
}
```

## Decision codes

Every `policy.Decision` carries a machine-readable `Code` (type `policy.DecisionCode`), set on every path the evaluator takes. Branch on it instead of parsing `Reason`. The same code appears in the JSON of a decision (`code`), on `toolguard` errors (`DeniedError.Code`, `ApprovalRequiredError.Code`, `TaintViolationError.Code`), in the audit metadata of policy decisions (`decision_code`) and in the 403 and 500 bodies of `RequirePolicy` (`decision_code`, next to the existing `code`). All of these are additive: `Reason` strings and existing keys are unchanged.

```go
err := guard.Authorize(ctx, call)
switch toolguard.CodeOf(err) { // finds the code with errors.As anywhere in the chain
case policy.CodeNoPermission, policy.CodeIPNotAllowed: // forbidden
case policy.CodeRateLimited: // retry later
case policy.CodeApprovalRequired, policy.CodeRiskEscalation: // ask a human
}
```

The values match the TypeScript library's `DECISION_CODES` one for one, so a client that handles both servers needs one vocabulary. Go defines no codes of its own. A "Reserved" code is defined for parity and is not produced yet; handle it anyway.

| Code | Meaning |
| --- | --- |
| `allowed` | An allow statement matched and nothing narrowed it. |
| `approval_consumed` | An escalated call went through because a human approval was spent (toolguard audit record). |
| `no_permission` | No allow statement matched (default deny), an explicit deny matched, or a permission boundary refused. |
| `rate_limited` | The per agent rate limit refused the call (`toolguard.Guard.Limit`). |
| `ip_not_allowed` | An allow statement covered the action and resource but its source IP condition failed. |
| `time_restricted` | An allow statement covered the action and resource but its time window condition failed. |
| `argument_rejected` | Reserved. A call argument was refused. |
| `approval_required` | A statement escalated the call and no valid approval was presented. |
| `approval_invalid` | An approval id was presented but could not be spent (unknown, pending, used or issued for another call). |
| `agent_not_found` | The agent id is unknown (reported when the limit check fails with `ErrAgentNotFound`). |
| `agent_revoked` | Reserved. The agent was revoked or suspended. |
| `agent_expired` | Reserved. The agent passed its expiry. |
| `invalid_token` | Reserved. The presented token failed verification. |
| `owner_mismatch` | Reserved. The caller does not own the agent. |
| `hook_denied` | A before authorize hook refused the call (see [hooks.md](hooks.md)). |
| `hook_timeout` | A before authorize hook did not answer within its timeout. The call is refused. |
| `hook_error` | A before authorize hook failed: an error, a panic, a malformed verdict, or a guard response that did not verify. The call is refused. |
| `taint_violation` | A taint rule refused or escalated the call. |
| `risk_escalation` | A risk tier turned an allow into an escalation. |
| `policy_indeterminate` | No decision could be reached (policies or subjects failed to load, no policy source, no agent id). Fail closed. |

## Rate limit

`RateLimit{Requests, Per, Burst}` is a token bucket per agent id: `Requests` per `Per`, with `Burst` as the bucket size (default `Requests`; `Per` defaults to one minute). It is spent by every mint, by `AuthorizeAgent` and by `CheckAgentRate`.

`AgentConfig.RateLimit` is the default for all agents. `ResolverV2` can return a `Resolution.RateLimit` for one agent, which replaces the default for that agent (`nil` keeps the default; a zero or negative value fails the mint closed). Buckets are keyed by agent id and remember their parameters, so a changed limit takes effect on the next request. `CheckAgentRate` (which has only an agent id) uses the limit that agent last had, so it never resets an overridden bucket. If both `Resolver` and `ResolverV2` are set, `ResolverV2` wins.

A mint over the limit answers `429` with a `Retry-After` header and `error=rate_limited`, the same shape as the endpoint limits in [oauth-endpoint-limits.md](oauth-endpoint-limits.md). `slow_down` is not used because RFC 8628 reserves it for device polling, and `temporarily_unavailable` is a 503 for server load, not a caller's budget.

The resolver runs before the budget is spent, because the budget can depend on it. Memory is bounded: the limiter tracks at most 10,000 agents and, when full, drops agents idle long enough to refill, then the least recently used one. The limiter is in process, so with several replicas each enforces its own budget.

## Limits of this release

- Per agent policy references and per agent rate limits are not stored on the agent row, because that needs a schema change in every storage backend. The `Resolver` is the way to attach policy to one agent: keep the agent to policy mapping in your IAM store.
- A per agent rate limit comes from the resolver, not from a stored field.

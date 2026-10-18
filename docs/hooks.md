# Lifecycle hooks

`Config.LifecycleHooks` lets a host react to authentication events without wrapping every route. All fields are optional. A runnable demo lives in [`examples/hooks`](../examples/hooks).

| Hook | Fires |
| --- | --- |
| `OnSignup(ctx, user, method)` | A user is created: password, magic link, OAuth callback, SAML, or a user's first passkey. |
| `OnSignin(ctx, user, session)` | A sign-in completes: password (no second factor), the TOTP or recovery-code step that finishes a password sign-in, magic link, OAuth callback, passkey login, SAML. Not for the pending second-factor session, step-up, or session rotation. |
| `OnPasswordChange(ctx, user)` | Password reset, change, or admin reset. |
| `OnMFAEnabled(ctx, user, kind)` | TOTP enrollment is confirmed (`MFAKindTOTP`). Recovery codes are created in that same step. Passkeys are a single-factor sign-in method here, so they do not fire it. `MFAKindWebAuthn` and `MFAKindRecoveryCodes` are reserved. |
| `OnOrgSwitch(ctx, user, orgID)` | `SetActiveOrganization`, including clearing it (empty `orgID`). |
| `OnTokenIssued(ctx, claims)` | Before an OAuth access token is signed. Can add claims and can fail issuance. |

The `otp` package proves control of a destination and issues no session, so it has no hook.

## Errors and panics

`OnSignup`, `OnSignin`, `OnPasswordChange`, `OnMFAEnabled` and `OnOrgSwitch` run after the action committed. The user row, the session or the new password hash already exists, and undoing it safely would need a coordinated storage transaction. They are therefore observe-only: a returned error is logged at Warn level and does not fail the request. A panic is recovered and logged.

To get alerted instead of only logging, set `OnHookError`:

```go
LifecycleHooks: &theauth.LifecycleHooks{
    OnSignup: provisionTenant,
    OnHookError: func(ctx context.Context, hook string, err error) {
        metrics.HookFailures.WithLabelValues(hook).Inc()
    },
}
```

`OnHookError` receives every hook error and every recovered panic (wrapped in an error). It runs synchronously, so keep it fast. A panic inside it is recovered.

## Refusing a signup or sign-in

There is no veto on an after-the-fact hook. To block a signup or sign-in before it commits, gate it where the identity is known up front: wrap the mounted route, or check the address before calling the library.

## Before authorize hooks and external guards

The lifecycle hooks above only observe. A before authorize hook can refuse: it sees an agent call after the agent is resolved and the agent policy allowed it, and it can deny the call, send it to approval, or let it through to the normal checks. The hook can run in process, or at a guard vendor's HTTPS endpoint through `hook.HTTPGuard`. Everything lives in `github.com/glincker/theauth-go/v2/policy/hook`.

```go
guard, err := hook.NewHTTPGuard(hook.HTTPGuardConfig{
    Name:   "hol-guard",
    URL:    "https://guard.example.com/theauth",
    Secret: os.Getenv("GUARD_SECRET"),
    Redact: func(in hook.Input) hook.Input { in.Arguments = nil; return in },
})
if err != nil {
    log.Fatal(err)
}
runner := &hook.Runner{Hook: hook.Compose(localRules, guard), Timeout: 1500 * time.Millisecond}

a, err := theauth.New(theauth.Config{
    // ...
    AgentIdentity: &theauth.AgentConfig{BeforeAuthorize: runner},
})

g := &toolguard.Guard{
    // ...
    BeforeAuthorize: runner,
    HookSubject:     a.AgentHookSubject,
}
```

`AgentConfig.BeforeAuthorize` covers `AuthorizeAgent`. `toolguard.Guard.BeforeAuthorize` covers guarded tool calls; set `HookSubject` to give the hook the agent's owner and delegation grants. Both fields are nil by default, and nil changes nothing.

### Outcomes

| Hook result | Call | Decision code |
| --- | --- | --- |
| allow | continues; theauth's own checks still decide | none |
| deny | refused | `hook_denied` |
| escalate | sent to the approval flow | `approval_required` |
| no answer within the timeout | refused | `hook_timeout` |
| error, panic, malformed verdict, bad guard response | refused | `hook_error` |

The hook runs only after the policy and the rate limit allowed (or escalated) the call, so a call the policy already refused never reaches a vendor. A hook allow never lifts a policy deny or a policy escalation. `AuthorizeAgent` returns an error that matches `ErrAgentPolicyDenied` and wraps a `*hook.BlockedError` with the code, and emits `agent.authorize_denied` with `decision_code` and a `hook` object (decision, code, guard, rule id, metadata, elapsed milliseconds). In toolguard a refusal is a `*toolguard.DeniedError` with the code, an escalate is an `*ApprovalRequiredError`, and a call the hook refused is always written to the audit log when `Guard.Audit` is set. An unknown or suspended agent, or a failure to load its delegations, refuses the call without asking the hook.

`hook.Compose` runs several hooks in order with deny overrides: the first deny wins and stops the run, otherwise an escalate beats allow. An error from any hook stops the run and denies.

### Timeout and fail closed

`Runner.Timeout` bounds one run. Zero uses `THEAUTH_HOOK_TIMEOUT_MS` (whole milliseconds, 1 to 60000), then 2 seconds. Anything above 60 seconds is clamped. The runner stops waiting at the deadline and cancels the hook's context. A hook must return once its context is done; one that ignores it keeps its goroutine until it returns, although the call was already refused. There is no fail open mode: every failure denies. `Runner.OnError` sees each timeout, error, panic and malformed verdict for metrics, and cannot change the outcome.

### Protocol 2026-10

`HTTPGuard` speaks the same wire protocol as the TypeScript library's `httpGuard`. Shared test vectors generated from the TypeScript code (`policy/hook/testdata/guard-vectors.json`) are checked byte for byte in the Go tests.

```http
POST /theauth HTTP/1.1
Content-Type: application/json
X-Theauth-Guard-Version: 2026-10
X-Theauth-Timestamp: 1792261200
X-Theauth-Signature: v1=5b0c...e1
X-Theauth-Key-Id: prod-1

{"version":"2026-10","requestId":"6f1c...","issuedAt":"2026-10-17T19:00:00.000Z",
 "input":{"agentId":"01J...","action":"read","resource":"mcp:github:issues",
 "arguments":{"q":"bugs"},"agent":{"id":"01J...","ownerId":"01H...","type":"autonomous","name":"bot"},
 "delegation":{"rootOwnerId":"01H...","path":["01J..."],"links":[],"inbound":[]},"source":"authorize","dryRun":false}}
```

The request signature is `v1=` plus the hex HMAC-SHA256, keyed with the shared secret, of `<timestamp>.<raw body>`. `X-Theauth-Key-Id` is sent only when `KeyID` is set. The vendor answers HTTP 2xx with two headers:

```http
X-Theauth-Response-Timestamp: 1792261200
X-Theauth-Response-Signature: v1=9d41...c7

{"decision":"deny","reason":"blocked by rule 7","code":"R7"}
```

The response signature is `v1=` plus the hex HMAC-SHA256 of `<requestId>.<response timestamp>.<raw response body>`, keyed with the shared secret (or `ResponseSecret`). The body is one of:

```json
{ "decision": "allow" }
{ "decision": "deny", "reason": "blocked by rule 7", "code": "R7" }
{ "decision": "escalate", "reason": "needs a human" }
```

`deny` needs a non-empty `reason` (it is returned to the calling agent, so keep secrets out) and may carry `code`. `allow` and `escalate` may carry `reason`. All three may carry `guard`, `ruleId` and `metadata` (at most 16 string, number or boolean values). `reason` is limited to 1024 characters, `code`, `guard` and `ruleId` to 128. `code` is reported as the rule id when `ruleId` is absent. Unknown fields, keys that differ only in case, `null` values, and trailing data are refused.

In the Go library the agent type is always `autonomous`, the delegation path is the agent alone, and `inbound` lists the agent's active delegation grants. A Go grant runs from a user to an agent, so its `fromAgent` is `user:<id>`.

### Vendor quickstart in Go

```go
func guardHandler(secret string, decide func(hook.Input) hook.Verdict) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(io.LimitReader(r.Body, hook.MaxBodyBytes))
        if err != nil {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        req, err := hook.VerifyGuardRequest(secret, r.Header, body, nil) // raw bytes, never re-encoded JSON
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        _ = hook.WriteGuardResponse(w, secret, req.RequestID, decide(req.Input))
    }
}
```

`VerifyGuardRequest` checks the headers, refuses timestamps more than 300 seconds from now (`VerifyOptions.Tolerance`), compares the signature in constant time, and parses the envelope. Pass `VerifyOptions.Seen` to refuse an exact replay of a request id inside the window. `WriteGuardResponse` checks the verdict against the schema, signs it for the request id, and writes it. For other stacks, `SignGuardResponse` returns the two headers and `SignGuardBody` and `VerifyGuardResponse` cover the client side. A vendor written in TypeScript uses `verifyGuardRequest` and `signGuardResponse` from `@glinr/theauth`; the bytes are the same.

For the conformance canaries, answer `allow` for resource `conformance:canary:allow` and `deny` for `conformance:canary:deny`. Treat `dryRun: true` as a question: do not count or alert on it.

### Security properties

- The URL must be https and must not carry credentials. Plain http is accepted only for `localhost`, `127.0.0.1` and `[::1]` with `AllowLoopback`, which is meant for a local vendor stub.
- Connections go through a dialer that refuses loopback, private, link local, CGNAT and cloud metadata addresses after DNS resolution, so a rebinding resolver cannot swap in an internal address. `AllowLoopback` opens loopback only; private ranges stay blocked. No proxy is used.
- Redirects are never followed, so a compromised endpoint cannot bounce the signed body elsewhere.
- Every response must carry a valid signature bound to the fresh request id and a timestamp inside the window. A hop without the secret cannot turn a deny into an allow, replay an old allow, or answer one request with another request's verdict. There is no switch to accept unsigned responses.
- Bodies over 64 KiB, non 2xx answers, redirects, malformed JSON and schema mismatches are errors, and every error denies.
- The secret is never sent, logged or put in an error. Errors name the endpoint origin only, not the path, query, headers or body, and the guard prints as `HTTPGuard(name at origin)`.
- The agent token and session data are never sent. `arguments` can hold user data: use `Redact` to drop or mask fields before they leave the process.
- Use `ResponseSecret` to keep the response key apart from the request key.
- Signing does not hide the request or the verdict (TLS does that), does not help if the secret leaks, and does not stop a vendor that signs a wrong answer.

### Differences from the TypeScript library

- No fail open mode (`onError: "allow"`) and no `requireSignedResponse: false`.
- Local http needs the explicit `AllowLoopback` option instead of `NODE_ENV`.
- `THEAUTH_HOOK_TIMEOUT_MS=0` does not disable the timeout; it falls back to 2 seconds.
- One request per check, no batching, no retries, no mTLS option yet.

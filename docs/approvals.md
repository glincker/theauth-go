# Approvals inbox

Mount `approvals.New` to let admins list, approve and deny agent tool approvals over HTTP.

```go
h, err := approvals.New(approvals.Config{
    Store: memStore, // must implement theauth.ToolApprovalAdminStorage
    Audit: memStore, // any theauth.AuditStorage
    Authenticate: func(r *http.Request) (string, error) { return mySession(r) }, // your auth
    IsAdmin: func(ctx context.Context, id string) bool { return isAdmin(ctx, id) },
})
mux.Handle("/approvals", h)
mux.Handle("/approvals/", h)
```

The handler does not invent a session system. `Authenticate` and `IsAdmin` are yours.

## Routes

| Route | Result |
| --- | --- |
| `GET /approvals?status=pending` | `{"approvals":[...]}`. Status is `pending`, `approved`, `denied`, `expired` or `consumed`; empty means all. |
| `POST /approvals/{id}/approve` | 200 with the updated approval |
| `POST /approvals/{id}/deny` | 200 with the updated approval |

Errors are RFC 7807 problem+json: 401 unauthenticated, 403 not an admin or self-approval, 404 unknown id, 409 already decided, spent or expired.

## Rules

- Four-eyes: the admin in `ToolApproval.OpenedBy` cannot decide the request unless `AllowSelfApproval` is true. An empty `OpenedBy` (an approval opened by an agent, not an admin) skips the check, so any admin can decide it.
- A decision is one conditional write in the store, so two concurrent decisions produce one 200 and one 409.
- Each decision writes one audit row (`tool_approval.approved` or `tool_approval.denied`) with the admin as actor and the agent as subject. If the audit write fails the response is 500 even though the decision stands.
- `Config.Arguments` is optional. Its output is redacted (keys containing password, secret, token, key, auth, cookie, credential, session, bearer, signature or code) and capped at 2 KB (`approvals.MaxArgumentBytes`). `Resource` and `Reason` are capped the same way.

## Limits

- Every built in store (memory, SQLite, Postgres, MySQL) implements `ToolApprovalAdminStorage`. SQL stores need the approval decisions migration (SQLite 0037, Postgres 0034, MySQL 0032), which adds `opened_by`, `denied_by`, `denied_at`, `expired_at` and `arguments_hash`.
- The inbox writes its own audit row per decision. If you also call `StorageApprovals.Decide` with `WithApprovalAudit`, route decisions through one path or you will get two rows.
- No built-in rate limit or pagination (list returns up to 100, newest first). Wrap the handler with your rate limiter.
- Run `storagetest.RunToolApprovalAdmin` against any store you add.

## Approvals in the tool guard

`policy/toolguard` opens, spends and reports approvals. This section is the flow a call goes through, from escalation to spend.

```go
store := memory.New() // or the sqlite, postgres or mysql store
hook, _ := toolguard.NewApprovalWebhook(toolguard.WebhookConfig{
    URL:    "https://ops.example.com/hooks/approvals",
    Secret: webhookSecret, // optional, signs the body with HMAC-SHA256
})
approvals := toolguard.NewStorageApprovals(store,
    toolguard.WithApprovalTTL(10*time.Minute),
    toolguard.WithApprovalAudit(auth.EmitAudit),
    toolguard.WithApprovalEvents(hook),
)
guard := &toolguard.Guard{Evaluator: ev, Policies: policies, Approvals: approvals}

call := toolguard.Call{AgentID: "agent-1", Tool: "pay", Args: map[string]any{"to": "bob", "amount": 500}}
err := guard.Authorize(ctx, call)
var need *toolguard.ApprovalRequiredError
if errors.As(err, &need) {
    // A human decides. This is what the inbox does for you over HTTP.
    _, _ = approvals.Decide(ctx, need.ApprovalID, toolguard.DecideInput{
        Decision: toolguard.DecisionApprove, DecidedBy: "alice@example.com",
    })
    // The retry spends the approval. It works once, for these exact arguments.
    err = guard.Authorize(toolguard.WithApprovalID(ctx, need.ApprovalID), call)
}
```

### Why a spend failed

A failed spend returns an `*ApprovalRequiredError` whose `Code` says why. Branch on it with `toolguard.CodeOf(err)`.

| Code | What to do |
| --- | --- |
| `approval_not_found` | The id is unknown. A new request is opened and its id is on the error. |
| `approval_pending` | Still waiting for a human. The error carries the same id, no second request is opened. |
| `approval_denied` | A human said no. No new request is opened, so an agent cannot ask the same person again by retrying. |
| `approval_expired` | The request passed its expiry before it was decided or spent. A new request is opened. |
| `approval_already_used` | Approvals are single use. A new request is opened. |
| `approval_mismatch` | The id was issued for another agent, action or resource. A new request is opened. |
| `approval_arguments_mismatch` | The arguments differ from the ones the human approved. A new request is opened for the new arguments. |

A custom `Approvals` that implements only `Open` and `Consume` still works and reports the generic `approval_invalid`. Implement `toolguard.Spender` to give it the specific codes.

### Arguments are bound

`Open` stores `toolguard.HashApprovalAction(action, resource, args)`: a SHA-256 of the canonical JSON of the action, the resource and the arguments. Object keys are sorted at every depth, so key order does not matter, and nil arguments hash like an empty object. Top level keys that belong to the library are left out of the hash, the same ones the TypeScript library strips: anything starting with `theauth` in any case, plus `approvalId` and `inputProvenance`. The guard audit metadata never copies tool arguments, so no separate stripping is needed there.

`toolguard.Tool` fills `Call.Args` from the typed arguments, so wrapped tools are bound without extra code. If you call `Authorize` directly, set `Call.Args`. Arguments that cannot be encoded as JSON (a channel, a cycle) make `Open` fail closed instead of storing an approval nobody could spend. The digest is stable inside this library. It is not promised byte for byte equal to the TypeScript digest for every input, so do not compare hashes across the two servers.

A request opened before the migration has an empty hash and covers any arguments until it expires.

### Single use and expiry

Spending is one conditional write in the store (`UPDATE ... WHERE approved_at IS NOT NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL AND not expired`) and success means one row changed, so two nodes racing for one approval produce one winner and the other gets `approval_already_used`. The read before it only picks the code. Approving and denying are conditional writes too, so a concurrent approve and deny leave exactly one decision. `storagetest.RunApprovalFlow` checks all of this against every store.

An approval past its expiry cannot be decided or spent. The first caller to notice marks it expired (`expired_at`), writes one `tool_approval.expired` audit row and sends one `approval.expired` event. `StorageApprovals.Cleanup` does the same for every overdue request, so you can run it on a timer.

### Audit rows, events and the webhook

With `WithApprovalAudit`, each step writes a row: `approval.request`, `tool_approval.approved`, `tool_approval.denied`, `tool_approval.expired` and `tool_approval.consumed`. The agent is the subject, the deciding human is the approver. The first three map to the shared events `approval.request`, `approval.approve` and `approval.deny`. Expiry and consumption keep an empty event.

With `WithApprovalEvents`, a sink sees `approval.pending`, `approval.approved`, `approval.denied` and `approval.expired`, each with a decision code (`approval_pending`, `approval_granted`, `approval_denied`, `approval_expired`) and the hash of the arguments, never the arguments. `NewApprovalWebhook` posts `approval.pending` to a URL (pass `Types` to send more). Delivery is asynchronous and best effort, and the optional secret signs the body in the `X-TheAuth-Signature` header as `sha256=<hex>`. The URL is operator configuration: do not build it from request data.

### Upgrading

- `StorageApprovals` and `MemoryApprovals` no longer report `approval_invalid`. Code that matched it should match the specific codes, or `toolguard.CodeOf(err).Permits()` and the `ApprovalRequiredError` type.
- A retry must pass the same arguments as the first call. A flow that put a timestamp or nonce in the arguments needs to keep it out of `Call.Args`.
- A pending id no longer opens a second request, and a denied id opens none.
- Run the SQL migration before deploying: SQLite 0037, Postgres 0034, MySQL 0032.

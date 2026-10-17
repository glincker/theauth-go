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

- Only the memory store implements `ToolApprovalAdminStorage`. SQL backends (SQLite, Postgres, MySQL) are not implemented: they keep `ToolApprovalStorage` only and need a migration for `opened_by`, `denied_by` and `denied_at` plus the three new methods.
- No built-in rate limit or pagination (list returns up to 100, newest first). Wrap the handler with your rate limiter.
- Run `storagetest.RunToolApprovalAdmin` against any store you add.

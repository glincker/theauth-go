# Querying the audit log

Read audit events through the admin endpoint or from Go with `QueryAudit`. Both accept the same filters and page with an opaque cursor.

## Admin endpoint

`GET /admin/v1/organizations/{orgID}/audit` needs the `audit:read` permission.

| Parameter | Meaning |
| --- | --- |
| `action` | Exact action string, for example `agent.created`. |
| `event` | Shared event name, for example `authorize` or `delegation.revoke`. See the list below. Needs write order support. |
| `target_type`, `target_id` | Exact match on the target. |
| `actor` | Actor user id (ULID). |
| `since`, `until` | RFC 3339 timestamps. |
| `order` | `desc` (default, newest write first) or `asc` (oldest write first). `asc` needs write order support. Anything else is a 400. |
| `limit` | Page size, 1 to 200, default 50. |
| `cursor` | The `next_cursor` of the previous page. Send it with the same `order` and filters. |

The response is `{"events": [...], "next_cursor": "..."}`. `next_cursor` is empty on the last page. The older `next` field carries the same value and stays for existing clients.

```sh
# First page of authorization events, oldest first
curl -s -H "Cookie: theauth_session=$TOKEN" \
  "https://auth.example.com/admin/v1/organizations/$ORG/audit?event=authorize&order=asc&limit=100"

# Next page
curl -s -H "Cookie: theauth_session=$TOKEN" \
  "https://auth.example.com/admin/v1/organizations/$ORG/audit?event=authorize&order=asc&limit=100&cursor=$NEXT"
```

Errors use the usual problem document (`application/problem+json`, with a `code`):

| Status | `code` | When |
| --- | --- | --- |
| 400 | `pagination.bad_cursor` | The cursor is malformed, truncated, or was issued for the other order. |
| 400 | `validation.invalid` | `order` is not `asc` or `desc`, or the storage backend cannot serve `order=asc`, the `event` filter or a `c1.` cursor. The query is refused, never silently run without the filter. |

## Order and cursors

Rows are ordered by the time they were written (`recordedAtUs`, microseconds, strictly increasing per organization), then by id. That is stable under concurrent writers, unlike the event's own `createdAt`, so a reader that follows `asc` pages sees every row exactly once. The stamp and the event name are not part of the audit hash chain.

Cursors beginning with `c1.` are opaque and bound to an order: a cursor from an `asc` read is rejected on a `desc` read. Cursors issued before write order existed keep working for `desc` reads. They are rejected for `asc`.

## From Go

```go
events, next, err := auth.QueryAudit(ctx, theauth.AuditQuery{
    Event: audit.EventAuthorize,
    Order: theauth.AuditOrderAsc,
    Limit: 100,
})
// next is the cursor for the following page: pass it as AuditQuery.After.
```

Errors to handle with `errors.Is`: `ErrBadAuditOrder`, `ErrBadCursor` and `ErrAuditOrderUnsupported`.

A backend declares support by returning true from `AuditOrderSupported()`. The bundled memory, SQLite, Postgres and MySQL stores do. A custom backend that does not gets `ErrAuditOrderUnsupported` for `asc`, `Event` and `c1.` cursors, and plain descending queries still work. See [storage capabilities](storage-capabilities.md).

## Events

The `event` column says what happened in a vocabulary shared with the TypeScript SDK. The action keeps its domain verb and is what the chain hashes. Every event the service writes gets its event from the action automatically, so call sites do not set it:

| Event | Actions |
| --- | --- |
| `authorize` | `agent.authorize`, `agent.authorize_denied` |
| `authorize.token` | `agent.token_minted`, `agent.token_denied` |
| `policy.evaluate` | `policy.decision` |
| `delegation.create`, `delegation.revoke` | `delegation.granted`, `delegation.revoked` |
| `agent.create`, `agent.revoke` | `agent.created`, `agent.revoked` |
| `agent.cascade.revoked` | `agent.cascade.revoked` |
| `approval.request` | `approval.request` |
| `approval.approve`, `approval.deny` | `tool_approval.approved`, `tool_approval.denied` |
| `vault.read` | `vault.token.issued` |
| `audit.write_failed` | `audit.events_dropped` |

Other actions (sessions, users, organizations, `agent.suspended`, and so on) have no event and are found with the `action` filter. A host that emits its own events can set one through `AuditMetadata.Event` on the context (`WithAuditMetadata`). A name outside the vocabulary is ignored, so a typo cannot create a value no filter finds.

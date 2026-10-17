# Dev mode

`theauth-dev` is the Go counterpart of `npx theauth dev`. It starts a local, in-memory TheAuth server, seeds it, and walks through the agent flow so you can see the whole loop in a few seconds.

```
go run github.com/glincker/theauth-go/v2/cmd/theauth-dev@latest
```

## What it does

1. Creates a user (`dev@example.com`).
2. Registers an agent (`support-agent`) owned by that user.
3. Grants the agent a delegation: `tickets.read` on a sample resource, for up to an hour.
4. Runs two tool calls through `policy/toolguard`. `search_tickets` is allowed by policy. `delete_records` is denied by an explicit deny statement.
5. Reads back the audit events, hashes them into a chain and verifies it.
6. Serves the library handler on `127.0.0.1` until you press Ctrl+C.

Sample output:

```
1. user       dev@example.com (01M5...)
2. agent      support-agent (01M5...) owned by that user
3. delegation [tickets.read] on https://api.example.com/mcp, up to 3600s
4. tool call ALLOWED search_tickets
5. tool call DENIED  delete_records
6. audit      5 events, hash chain verified (head 1f96afba402b)
```

## Flags

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--port` | `THEAUTH_DEV_PORT` | `3100` | Port to listen on. Always bound to `127.0.0.1`. The flag wins over the env var. |
| `--smoke` | | off | Run the walkthrough, print `smoke: ok` and exit 0 without starting the server. Exits non-zero if any step fails. |

## Limits

Everything lives in memory and is gone when the process exits. A fresh signing key is generated on each start.

The memory store keeps no native audit hash chain, so the walkthrough builds a SHA-256 chain over the recorded events and re-walks it. That shows the sequence is intact in this process. For production, use the sqlite, postgres or mysql store, which chain every row and expose `(*TheAuth).VerifyAuditChain`.

For the real wiring, read `examples/agent-tool-guard` and `examples/agent-policy`, and see [agent-policies.md](agent-policies.md).

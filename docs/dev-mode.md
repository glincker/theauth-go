# Dev mode

Local in-memory server with a seeded agent walkthrough (Go counterpart of `npx theauth dev`):

```sh
go run github.com/glincker/theauth-go/v2/cmd/theauth-dev@latest
```

```
1. user       dev@example.com (01M5...)
2. agent      support-agent (01M5...) owned by that user
3. delegation [tickets.read] on https://api.example.com/mcp, up to 3600s
4. tool call ALLOWED search_tickets
5. tool call DENIED  delete_records
6. audit      5 events, hash chain verified (head 1f96afba402b)
```

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--port` | `THEAUTH_DEV_PORT` | `3100` | Listen port, always `127.0.0.1`. The flag wins over the env var. |
| `--smoke` | | off | Run the walkthrough, print `smoke: ok`, exit 0 without serving. Non-zero exit if any step fails. |

The walkthrough:

1. Creates user `dev@example.com`.
2. Registers agent `support-agent` owned by that user.
3. Grants delegation `tickets.read` on a sample resource, up to one hour.
4. Runs two tool calls through `policy/toolguard`: `search_tickets` is allowed, `delete_records` is denied by an explicit deny statement.
5. Reads the audit events, hashes them into a SHA-256 chain and verifies it.
6. Serves the handler on `127.0.0.1` until Ctrl+C.

## Limits

- All state is in memory and is lost on exit. A new signing key is generated on each start.
- The memory store has no native audit hash chain. The command builds the chain itself, so it only shows the sequence is intact in this process.
- Production: use the sqlite, postgres or mysql store. They chain every row and expose `(*TheAuth).VerifyAuditChain`.
- Real wiring: see `examples/agent-tool-guard`, `examples/agent-policy` and [agent-policies.md](agent-policies.md).

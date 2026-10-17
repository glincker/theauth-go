<!-- Paste this section into your project's CLAUDE.md. -->

## theauth-go

This project uses theauth-go.

### How to wire theauth-go

- Module: `github.com/glincker/theauth-go/v2` (Go 1.25+). Resource server SDK for MCP servers: `github.com/glincker/theauth-go/mcpresource` (separate module, stdlib only). Read the package docs (`go doc`) before using an option. Do not invent APIs.
- One instance at startup:

```go
import (
    "github.com/glincker/theauth-go/v2"
    "github.com/glincker/theauth-go/v2/storage/memory" // dev only; use postgres, mysql or sqlite in production
)

a, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "https://app.example.com"})
// check err
a.Mount(r) // chi router; wires /auth/*
r.With(a.RequireAuth()).Get("/me", handler) // user, ok := theauth.UserFromContext(r.Context())
```

- OAuth 2.1 server and agents are opt in: set `Config.AuthorizationServer` (needs a 32 byte `Config.EncryptionKey`) and `Config.AgentIdentity`. Create agents with `a.CreateAgent` and record user approval with `a.GrantDelegation`.
- Agent tool calls go through `policy/toolguard`: build a `toolguard.Guard` and wrap each tool with `toolguard.Tool(g, buildCall, fn)`. Handle `*toolguard.DeniedError` and `*toolguard.ApprovalRequiredError`, and retry with `toolguard.WithApprovalID(ctx, id)` after a human approves. Example: `examples/agent-tool-guard`.
- MCP servers validate tokens with `mcpresource.New(resourceURI, mcpresource.WithJWKS(...), mcpresource.WithIntrospection(...))`, then `v.Middleware` and `v.RequireScope`. DPoP: `Config.DPoP` on the server, `mcpresource.WithDPoPVerification(...)` on the resource server.
- Run `go vet ./...` and the package tests after edits.

### Security rules (do not break these)

1. Never log, print, return in an error, or commit tokens. That covers session cookies, bearer and refresh tokens, DPoP proofs, client secrets, registration tokens and `Config.EncryptionKey`. Redact `Authorization` headers in request logs. Pass the raw cookie token to the library, never store it yourself.
2. Always verify delegation. Do not trust a caller's claim that an agent acts for a user. Use `mcpresource` (it rechecks tokens with an `act` claim or `delegation_grant_id` against introspection) and read `Principal.Subject` and `Principal.ActorChain`. Delegation only narrows scope and duration, and the chain depth cap is 3. Never widen it.
3. Policy is deny by default. Treat deny, escalation and any evaluation error as "do not run". Never turn an error into an allow. Do not add catch-all `*` statements to make a test pass.
4. Every tool an agent can call goes through `toolguard.Tool`. Approvals are single use.
5. Use DPoP-bound tokens for MCP access tokens that leave your trust boundary. Use a shared replay cache when you run more than one replica.
6. Redirect URIs are matched exactly. Never use prefix, substring or wildcard matching. PKCE S256 is mandatory. Dynamic client registration stays denied unless `RegistrationTokens` is set.
7. Set `Config.TrustedProxies` only to your real proxy CIDRs. Do not use `email.Noop` in production.
8. Do not bypass `RequireAuth()` with hand-written session checks, and do not turn off rate limits to get a test green.

# theauth-go rules

Module `github.com/glincker/theauth-go/v2` (Go 1.25+). MCP resource server SDK: `github.com/glincker/theauth-go/mcpresource` (separate module, stdlib only). Read `go doc` before using an option. Do not invent APIs.

```go
import (
    "github.com/glincker/theauth-go/v2"
    "github.com/glincker/theauth-go/v2/storage/memory" // dev only; postgres, mysql or sqlite in production
)

a, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "https://app.example.com"})
// check err
a.Mount(r) // chi router; wires /auth/*
r.With(a.RequireAuth()).Get("/me", handler) // user, ok := theauth.UserFromContext(r.Context())
```

## Must

- Create one instance at startup. OAuth 2.1 server and agents are opt in: `Config.AuthorizationServer` (needs a 32-byte `Config.EncryptionKey`) and `Config.AgentIdentity`.
- Wrap every agent tool with `toolguard.Tool(g, buildCall, fn)`. Handle `*toolguard.DeniedError` and `*toolguard.ApprovalRequiredError`, and retry with `toolguard.WithApprovalID(ctx, id)` after approval. Approvals are single use.
- Verify delegation through `mcpresource`, and read `Principal.Subject` and `Principal.ActorChain`. Delegation only narrows scope and duration. Chain depth cap is 3.
- Deny by default. Treat deny, escalation and any evaluation error as do not run.
- Use DPoP-bound tokens (`Config.DPoP`, `mcpresource.WithDPoPVerification(...)`) for MCP access tokens that leave your trust boundary. Share the replay cache across replicas.
- Match redirect URIs exactly. PKCE S256 is mandatory.
- Set `Config.TrustedProxies` only to your real proxy CIDRs.
- Run `go vet ./...` and the package tests after edits.

## Never

- Log, print, return in errors or commit tokens: session cookies, bearer and refresh tokens, DPoP proofs, client secrets, registration tokens, `Config.EncryptionKey`. Redact `Authorization` in request logs. Pass the raw cookie token to the library, never store it yourself.
- Turn an error into an allow, or add catch-all `*` statements to make a test pass.
- Widen delegation.
- Use prefix, substring or wildcard redirect matching.
- Allow dynamic client registration unless `RegistrationTokens` is set.
- Use `email.Noop` in production.
- Bypass `RequireAuth()` with hand-written session checks, or turn off rate limits to get a test green.

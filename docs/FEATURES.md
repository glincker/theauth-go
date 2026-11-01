# Features and use cases

Moved from the README.

## What you can build

### Add sign-in to a Go web app

Email and password, magic links, 12 OAuth login providers, generic OIDC and 16 more catalog providers, with server-side sessions. Start with the [net/http quick start](../README.md#quickstart) or the [Gin](../adapters/gin), [Echo](../adapters/echo) and [Fiber](../adapters/fiber) adapters. Guide: [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider).

### Run an OAuth 2.1 authorization server in Go

Authorization code with PKCE, refresh rotation, `client_credentials`, token exchange, PAR, JAR, CIBA and DPoP, with dynamic client registration and client ID metadata documents. Guide: [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server).

### Secure an MCP server

Use theauth-go as the authorization server for MCP clients, and the separate `mcpresource` module to validate tokens and guard tools in your MCP resource server. Example: [`examples/mcp-server`](../examples/mcp-server). Guides: [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization), [Protect MCP tools](https://docs.theauth.dev/go/guides/protect-mcp-tools).

### Passkeys and WebAuthn

Discoverable passkey login and TOTP with recovery codes, plus step-up checks with `RequireRecentAuth`. Example: [`examples/webauthn-passkey`](../examples/webauthn-passkey). Guide: [Enable passkeys](https://docs.theauth.dev/go/guides/webauthn-passkeys).

### Device login for Go CLIs

RFC 8628 device authorization on the server and the `clientauth` package in your CLI. Example: [`examples/cli-login`](../examples/cli-login). Guide: [CLI login](https://docs.theauth.dev/go/guides/cli-login).

### SAML SSO and SCIM provisioning

SAML 2.0 single sign-on, SCIM 2.0 user provisioning, organizations, RBAC and an append-only audit log with Splunk, webhook and OTLP sinks. Needs memory, SQLite, Postgres or MySQL storage. Guide: [Splunk audit streaming](https://docs.theauth.dev/go/guides/audit-log-splunk).

### Create a user for an existing identity

`CreateUser` adds a user row without sending email or creating a credential or session. It is idempotent on the normalized email, so calling it on every login of an external identity provider is safe, even concurrently. Typed errors match `ErrUserInvalidInput`, `ErrUserEmailConflict` and `ErrUserIDConflict` with `errors.Is`. Details: [docs/create-user.md](./create-user.md).

```go
u, err := a.CreateUser(ctx, theauth.CreateUserInput{Email: "ada@example.com", Name: "Ada"})
```

### Agent identity and delegation

Give an AI agent its own credential and let it act for a user with a narrower scope. See the [agent quick start](./AGENT-QUICKSTART.md).

## Features

| Area | What you get | Docs |
|---|---|---|
| Sign-in | Email and password (Argon2id, 12 character minimum), magic links, 12 OAuth login providers, generic OIDC | [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) |
| Second factors | WebAuthn passkeys with discoverable login, TOTP with recovery codes, step-up with `RequireRecentAuth` | [Enable passkeys](https://docs.theauth.dev/go/guides/webauthn-passkeys) |
| Sessions | Opaque server-side sessions, session list and revoke, idle timeout | [Configuration](https://docs.theauth.dev/go/reference/configuration) |
| API tokens and CLIs | Scoped tokens with `RequireAbility`, RFC 8628 device login via the `clientauth` package | [API tokens](https://docs.theauth.dev/go/guides/api-tokens), [CLI login](https://docs.theauth.dev/go/guides/cli-login) |
| OAuth 2.1 server | Authorization code with PKCE, refresh rotation, `client_credentials`, token exchange, CIBA, PAR, JAR, DPoP | [OAuth 2.1 primer](https://docs.theauth.dev/go/concepts/oauth21-primer), [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server) |
| Token policy, RAR and ID-JAG | Per-client signing algorithm (EdDSA, ES256, RS256) and opaque access tokens, RFC 9396 `authorization_details` end to end, and ID-JAG issue and redeem over token exchange and jwt-bearer | [Token policy](./access-token-policy.md), [RAR](./rich-authorization-requests.md), [ID-JAG](./id-jag.md) |
| OpenID Provider | ID tokens with nonce and `at_hash`, userinfo, RP-initiated and back-channel logout, pairwise subjects, OpenID discovery fields | [OpenID Provider](./oidc-provider.md) |
| Multi-replica and abuse controls | Pluggable rate limiter, DPoP replay cache and CIMD cache (memory, SQL, Redis or your own), per-IP and per-client limits and an Argon2id concurrency cap on the OAuth endpoints | [Pluggable stores](./pluggable-stores.md), [Endpoint limits](./oauth-endpoint-limits.md), [Request admission](./admission.md) |
| Browserless OAuth | RFC 8628 device authorization grant on the authorization server with a themable verification page, plus scoped one-time registration tokens for agents | [Device grant](./device-authorization.md), [Registration tokens](./registration-tokens.md) |
| One-time codes | Email and SMS OTP with pluggable senders (Twilio built in), resend cooldown, attempt limit, lockout, constant-time compare | [OTP](./otp.md) |
| More sign-in providers | Table-driven catalog of 16 more OAuth providers, custom specs, and OIDC discovery overrides | [Provider catalog](./provider-catalog.md) |
| Developer CLI and OpenAPI | `theauth-go secret` and `theauth-go openapi`, plus `openapi.Generate` for your own router | [CLI](./cli.md) |
| MCP and agents | MCP authorization (protected resource metadata, CIMD), agent identities with delegation, `mcpresource` SDK module (scope and step-up guards, tool security metadata) | [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization), [Resource server](https://docs.theauth.dev/go/concepts/resource-server), [Protect MCP tools](https://docs.theauth.dev/go/guides/protect-mcp-tools) |
| Enterprise | SAML 2.0 SSO, SCIM 2.0, organizations, RBAC, append-only audit log with SIEM sinks | [Splunk audit streaming](https://docs.theauth.dev/go/guides/audit-log-splunk), [Threat model](https://docs.theauth.dev/go/security/threat-model) |
| Policy | Authorization policy engine | [Policy engine](https://docs.theauth.dev/go/guides/policy-engine) |
| Observability | OpenTelemetry spans, Prometheus metrics | [OpenTelemetry tracing](https://docs.theauth.dev/go/guides/opentelemetry-tracing), [Metrics](https://docs.theauth.dev/go/reference/metrics) |
| Supply chain | SBOM and Sigstore signed release artifacts, SLSA 3 provenance | [Releases and verification](https://docs.theauth.dev/go/security/releases) |

## Running more than one replica

Rate limits, DPoP replay records and the CIMD cache are per process by default. Share them through the database you already have:

```go
db := stdlib.OpenDBFromPool(pool) // pgx stdlib
kvStore, _ := sqlkv.New(db, sqlkv.Postgres)
_ = kvStore.EnsureSchema(ctx)

auth, _ := theauth.New(theauth.Config{
    // ...
    Stores: kv.FromCache(kvStore), // or kv/redis, or your own kv.RateLimiter / kv.ReplayCache / kv.Cache
})
```

Details and the Redis adapter are in [docs/pluggable-stores.md](./pluggable-stores.md).

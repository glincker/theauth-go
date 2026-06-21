# Why MCP OAuth 2.1 matters

A short, opinionated take on the Go auth stack a team needs to ship a
production MCP server in 2026.

## The problem

The Model Context Protocol turned every AI agent into an OAuth client. The
2025-11-25 MCP spec mandates OAuth 2.1 with PKCE for any MCP server that
exposes tools, and the draft revision lands stricter audience binding plus
delegation chains (RFC 8693) on top. The job of the auth layer is no longer
"sign the user in." It is:

1. Stand up an OAuth 2.1 authorization server that mints RFC 9068 JWT
   access tokens bound to a specific resource via RFC 8707.
2. Mint long-lived identities for the agents the user trusts (the
   `client_credentials` grant on a per-agent client).
3. Record the user's revocable permission for an agent to act on a
   specific resource (a delegation grant), and at every token-exchange
   call verify the grant is still alive, narrow the scope, narrow the
   duration, and cap the actor chain.
4. On the resource server side, validate the token, walk the actor chain,
   and reject the request the moment any link in the chain is revoked.
5. Publish discovery documents (RFC 8414, RFC 9728) so a fresh MCP client
   can find every piece of the stack without out-of-band configuration.

Every piece above is a separate spec. Every piece is required. Most existing
Go auth libraries stop at step 1; the rest leave you to glue together five
RFCs in a deployment you cannot afford to get wrong.

## What theauth-go ships

`theauth-go` v2.0 is the first Go auth library where every layer above ships
in a single module, with a single import, behind one stable surface:

- A drop-in OAuth 2.1 AS with mandatory PKCE S256, RFC 8707 audience
  binding, RFC 9068 EdDSA JWT access tokens, RFC 9700 refresh rotation
  with family revocation, and RFC 7591 dynamic client registration.
- First-class agent identities. An agent is a user-owned or
  organization-owned record with its own client credentials, its own
  audit identity (`actor_agent_id` on every event), and its own
  lifecycle (active, suspended, revoked).
- Revocable delegation chains. The RFC 8693 token-exchange grant accepts
  a subject token plus an actor token, looks up the matching delegation
  grant, narrows the scope to the strict intersection of the subject's
  scope and the grant's scope, narrows the duration to the smaller of
  the requested TTL and the grant's `max_duration_seconds`, caps the
  chain depth at 3, and emits a new JWT with a nested `act` claim.
  Revoking a delegation flips every derived token's introspection result
  to `active=false` inside `IntrospectionCacheTTL` (default 60 seconds).
- A separate, zero-dependency Go module for the resource server side.
  `import "github.com/glincker/theauth-go/mcpresource"`, wire one
  middleware, and your MCP server gets JWT validation, audience
  enforcement, actor-chain walking, and RFC 9728 metadata pointers in
  the WWW-Authenticate header. The package has no third-party
  dependencies: a consumer importing it does not transitively pull
  theauth core or any storage adapter.
- Operator and end-user UX. Admins manage agents and delegations via
  `/admin/v1/organizations/{orgID}/agents` and `/delegations` with
  RFC 7807 problem+json errors. End users self-serve via `/account/agents`
  and `/account/delegations`. Both surfaces emit the same audit events
  the service layer emits, so the SOC 2 story is uniform.

## The one-import claim, illustrated

```go
package main

import (
    "net/http"

    "github.com/glincker/theauth-go/mcpresource"
    "github.com/go-chi/chi/v5"
)

func main() {
    v := mcpresource.New(
        "https://mcp.example.com",
        mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
        mcpresource.WithIntrospection(
            "https://as.example.com/oauth/introspect",
            "mcp-client-id",
            "mcp-client-secret",
        ),
    )

    r := chi.NewRouter()
    r.Use(v.Middleware)
    r.Get("/tools/run", func(w http.ResponseWriter, r *http.Request) {
        p, _ := v.Principal(r.Context())
        // p.Subject is the originating user (or root agent).
        // p.Actor is the innermost agent currently acting.
        // p.ActorChain walks innermost to outermost.
    })

    _ = http.ListenAndServe(":8090", r)
}
```

That is the entire integration. Audience binding, signature verification,
chain walking, revocation propagation, and the RFC 9728 metadata pointer in
the 401 response all happen behind the middleware. The validator caches
JWKS keys and introspection responses for 60 seconds by default; tune with
`WithCacheTTL`.

## Compliance summary

The v2.0 surface implements (or interoperates with) the following RFCs and
specs:

- RFC 6749 OAuth 2.0 Authorization Framework (selected grants).
- RFC 6750 Bearer Token Usage (WWW-Authenticate, error codes).
- RFC 7517 JSON Web Key.
- RFC 7591 OAuth 2.0 Dynamic Client Registration.
- RFC 7592 OAuth 2.0 Dynamic Client Registration Management.
- RFC 7636 PKCE (S256 only, mandatory).
- RFC 7662 OAuth 2.0 Token Introspection.
- RFC 7807 Problem Details for HTTP APIs (admin surface).
- RFC 8414 OAuth 2.0 Authorization Server Metadata.
- RFC 8693 OAuth 2.0 Token Exchange (`act` chain depth 3 cap, scope and
  duration narrowing).
- RFC 8707 Resource Indicators (mandatory).
- RFC 9068 JWT Profile for OAuth 2.0 Access Tokens (EdDSA / Ed25519).
- RFC 9728 OAuth 2.0 Protected Resource Metadata.
- RFC 9700 OAuth 2.0 Best Current Practices (refresh-token rotation with
  family revocation on replay).
- OAuth 2.1 draft (no implicit grant, no password grant, PKCE mandatory).
- MCP Authorization specification (2025-11-25 and the draft revision).

## Positioning, one sentence

`theauth-go` v2.0 is the first Go auth library where OAuth 2.1 MCP AS,
agent identities, and revocable delegation chains are a single import.

## Where it goes next

- Hardware-attested agent credentials (TPM-backed signing keys) on the
  agent-side. The `AgentCredentialKindJWK` and `AgentCredentialKindX509`
  paths are reserved.
- Budget policies (per-resource spend caps that cascade into the actor
  chain). The audit and delegation tables already carry the fields a
  budget enforcer would need.
- A `pinchtab`-style local MCP harness for integration tests against the
  full stack.

The v2.0 release is the production cut. v2.1 will land additive features
behind optional config blocks; v1.0 callers see no behavioural change.

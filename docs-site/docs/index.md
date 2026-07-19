# theauth-go

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareSourceCode",
  "name": "theauth-go",
  "description": "OAuth 2.1 authorization server and auth library for Go: sessions, magic links, WebAuthn/passkeys, TOTP, SAML, SCIM, RBAC, and MCP resource-server authorization. Postgres, MySQL, and in-memory storage.",
  "codeRepository": "https://github.com/glincker/theauth-go",
  "url": "https://theauth.dev/go/",
  "programmingLanguage": "Go",
  "license": "https://github.com/glincker/theauth-go/blob/main/LICENSE",
  "runtimePlatform": "Go 1.25+",
  "applicationCategory": "Authentication Library",
  "keywords": "oauth2, oidc, mcp, mcp-authorization, golang, authorization-server, passkeys, webauthn, saml, scim, rbac, totp, jwt",
  "author": {
    "@type": "Organization",
    "name": "GLINR Studios",
    "url": "https://github.com/glincker"
  }
}
</script>

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go.svg)](https://pkg.go.dev/github.com/glincker/theauth-go)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/glincker/theauth-go/blob/main/LICENSE)

**The first Go auth library where OAuth 2.1 MCP authorization, agent identities, and revocable delegation chains ship in a single import.**

Drop it into a `chi` or `net/http` server in under twenty lines. Store sessions in Postgres or memory.

## Install

```bash
go get github.com/glincker/theauth-go
```

Requires **Go 1.25+**.

## Quick Start

```go
package main

import (
    "net/http"

    "github.com/glincker/theauth-go"
    "github.com/glincker/theauth-go/storage/memory"
    "github.com/go-chi/chi/v5"
)

func main() {
    a, _ := theauth.New(theauth.Config{
        Storage: memory.New(),
        BaseURL: "http://localhost:8080",
    })

    r := chi.NewRouter()
    a.Mount(r)

    r.With(a.RequireAuth()).Get("/me", func(w http.ResponseWriter, r *http.Request) {
        user, _ := theauth.UserFromContext(r.Context())
        w.Write([]byte("hello " + user.Email))
    })

    http.ListenAndServe(":8080", r)
}
```

Run it:

```bash
go run main.go
# POST http://localhost:8080/auth/magic-link  {"email":"you@example.com"}
```

## What it covers

| Area | Capability |
|---|---|
| Identity | Magic links, email/password (Argon2id), WebAuthn passkeys, TOTP, OAuth providers |
| Enterprise | SAML 2.0 SP, SCIM 2.0, multi-tenancy organizations, RBAC |
| OAuth 2.1 AS | Authorization code + PKCE, refresh rotation, DCR, EdDSA JWTs, audience binding |
| MCP | Agent identities, revocable delegation chains (RFC 8693), resource-server SDK |
| Hardening | Audit log, rate limiting, fuzz tests, benchmark gate, OTel/Prom adapter |

## Documentation

- [Getting Started](getting-started/overview.md) - Installation, quick start, storage backends
- [Concepts](concepts/oauth21-primer.md) - OAuth 2.1, MCP authorization, AS/RS roles
- [Guides](guides/add-oauth-provider.md) - Step-by-step task guides
- [Reference](reference/configuration.md) - Config shape, errors, metrics, spans, audit events
- [Security](security/threat-model.md) - Threat model, release verification
- [Migrations](migrations/v2.0-to-v2.1.md) - Upgrade guides between versions
- [Changelog](changelog.md) - Full release history

## MCP Resource Server

For MCP servers that only need token validation (no auth server), install the zero-dependency SDK:

```bash
go get github.com/glincker/theauth-go/mcpresource
```

```go
v := mcpresource.New(
    "https://mcp.example.com",
    mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
    mcpresource.WithIntrospection(
        "https://as.example.com/oauth/introspect",
        "mcp-client-id", "mcp-client-secret",
    ),
)
r.Use(v.Middleware)
```

See [Resource Server (mcpresource)](concepts/resource-server.md) for the full walkthrough.

# Changelog

All notable changes to theauth-go are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) from v1.0 forward.

## [Unreleased]

### Added (v0.7)

- SAML 2.0 Service Provider on top of `github.com/crewjam/saml` v0.5.1.
  Per-connection IdP binding stored in `saml_connections`, signed
  assertions only (raw-XML signature gate before parse), find-or-create
  by `(connection_id, name_id)` with an email fallback, AuthnRequest
  replay tracking with a configurable TTL. Public-facing flow at
  `/auth/saml/{connectionId}/{login,acs,metadata}`. Per-organization
  connection CRUD at `/auth/orgs/{orgId}/saml/connections`.
- SCIM 2.0 provisioning (RFC 7643 + RFC 7644). Users + Groups CRUD,
  discovery endpoints (`ServiceProviderConfig`, `ResourceTypes`,
  `Schemas`), eq-only filter parser, RFC 7644 PATCH (add / replace /
  remove). Bearer auth with sha256-hashed 256-bit tokens, HTTPS
  enforcement, per-organization isolation, idempotent upsert by
  `externalId`. PUT returns 405 (documented deviation; Okta and Azure AD
  default to PATCH). Endpoints live under `/scim/v2/`. Per-organization
  token CRUD at `/auth/orgs/{orgId}/scim/tokens`.
- Organizations multi-tenancy: `organizations`, `organization_members`,
  `sessions.active_organization_id`. Roles: `owner`, `admin`, `member`.
  Single-tenant deployments leave `Config.Organizations` nil and see no
  behavior change.
- Migrations: `0006_organizations`, `0007_saml`, `0008_scim` (additive
  on `users.external_id`, `users.given_name`, `users.family_name`,
  `users.display_name`).
- Audit hook (`Config.AuditHook`): synchronous no-op stub invoked on
  every SCIM mutation and every successful SAML assertion. v1.0 replaces
  the default binding with the real async writer; the consumer-facing
  signature stays stable.
- Test fixtures: `internal/samltest` generates a fresh IdP keypair and
  signs assertions in-process for the SAML end-to-end tests. SCIM tests
  exercise the Okta / Azure AD provisioning cycle (create, patch,
  deactivate, idempotent re-create, delete).

### Added (v0.6 hardening)

- Fuzz tests for every external byte boundary: AES-GCM encrypt and decrypt
  round-trip, decrypt arbitrary input, PKCE verifier to challenge, PKCE
  verifier generation, token hash round-trip, base64 URL decode, session
  cookie parsing, OAuth state cookie parsing, email validation, OAuth
  callback query parameters, and OAuth callback provider name routing.
- Concurrency tests covering the OAuth state map, the in-memory rate
  limiter (same IP and different IP fan-out), and session creation under
  contention. All assertions hold under `go test -race`.
- Benchmark suite under `internal/bench` measuring password sign in,
  session lookup, OAuth callback storage cost, magic link consume, and
  PKCE challenge derivation. Baselines are recorded in
  `internal/bench/BASELINES.md`.
- Four new runnable example apps: `examples/gin-app`,
  `examples/echo-app`, `examples/stdlib-app`, and
  `examples/oauth-multi-provider`, each with a README, single-file
  `main.go`, `go.mod`, `docker-compose.yml`, `.env.example`, and
  `Makefile`.
- Package documentation: `doc.go` added for every package, doc comments
  filled in on previously undocumented exports, runnable `Example`
  functions for the most-used entry points.
- `STABILITY.md` enumerating the stable surface and the rules that
  govern future changes.
- `golangci.yml` enables `godot` and `godox` to keep doc comments
  punctuated and to flag stray `TODO` markers.
- CI workflow now runs a per-target fuzz job (`-fuzztime=10s`) on every
  PR alongside the existing race-enabled test job.

### Notes

- No new features. Hardening only.
- No public API changes. Existing callers compile and run unchanged.

## [v0.5.0] - 2026-06-19

WebAuthn passkeys, TOTP second factor with recovery codes, session
step-up via `pending_2fa`. See git history for the full set of changes.

## [v0.4.0]

Discord OAuth provider. PKCE-aware flow shared across all four
providers.

## [v0.3.0]

GitHub, Google, and Microsoft OAuth providers. AES-256-GCM at-rest
encryption for provider tokens. Per-IP rate limiter.

## [v0.2.0]

Email and password credentials with Argon2id. Password reset via
single-use token.

## [v0.1.0]

Initial release: magic-link email auth, opaque session tokens with
revocation, chi-friendly middleware, in-memory and Postgres storage
adapters.

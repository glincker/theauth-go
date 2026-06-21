# Changelog

All notable changes to theauth-go are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) from v1.0 forward.

## [1.0.0] - 2026-06-20

First production-ready release. Public API frozen per STABILITY.md. From
v1.0 forward, breaking changes require a major bump; minor releases add
optional config fields, new methods, new error sentinels, new audit
actions, and new `Stats` fields without breaking existing callers.

### v0.1 to v1.0 capability summary

- Magic-link sign-in, opaque sessions, pluggable `Storage` (memory + postgres).
- Email + password with Argon2id, password reset via single-use token.
- OAuth 2.0 + OIDC with PKCE S256; built-in GitHub, Google, Microsoft, Discord.
- WebAuthn / passkey registration and discoverable login.
- TOTP second factor with salted SHA-256 recovery codes; session step-up via `pending_2fa`.
- SAML 2.0 Service Provider for enterprise IdPs (per-connection + per-org).
- SCIM 2.0 Users + Groups with eq-only filter and RFC 7644 PATCH.
- Organization multi-tenancy with `active_organization_id` session scope.
- Organization-scoped RBAC with a closed permission catalog and seeded roles.
- Append-only audit log with async batched writes, default redactor, keyset cursor read API.
- Admin HTTP API at `/admin/v1` with RFC 7807 problem+json errors.
- Fuzz tests, race-clean test suite, godoc with examples, finalized `STABILITY.md`.

### Added in 1.0

- RBAC: `permissions`, `roles`, `role_permissions`, `user_roles` tables and the
  matching `Storage` methods. `(*TheAuth).RequirePermission` middleware with a
  per-request cache. `SeedPermissions`, `SeedOrganizationRoles`,
  `GrantRole`, `RevokeRole`, `CreateRole`, `UpdateRole`, `DeleteRole`,
  `PermissionsForUser`, `HasPermission`. Twelve seeded permission constants
  plus the system `super_admin` role (granted out-of-band only).
- Audit log: `audit_events` table with org / actor / action DESC indexes.
  `(*TheAuth).EmitAudit` is non-blocking; the writer goroutine drains in
  batches and flushes on `Close` with a configurable timeout. `Stats`
  exposes four atomic counters (`AuditEmitted`, `AuditWritten`,
  `AuditDropped`, `AuditFailed`). `DefaultRedactor` masks
  `password / secret / token / code / refresh_token / access_token` at any
  nesting depth. Twenty-plus canonical actions emitted across every
  state-changing handler in theauth.
- Admin API: twelve endpoints under `/admin/v1` (overridable via
  `AdminConfig.PathPrefix`). Every endpoint requires `RequireAuth` plus a
  catalog `RequirePermission`. Errors are `application/problem+json` per
  RFC 7807 with a stable `code` extension; keyset pagination on the audit
  read endpoint.
- `(*TheAuth).Start` spawns the writer goroutine; `New` invokes `Start`
  automatically so existing callers do not change. `Close` drains the
  writer with a default 5 second deadline.
- New errors: `ErrAdminRequiresRBAC`, `ErrForbidden`, `ErrUnknownPermission`,
  `ErrRoleInUse`, `ErrNoActiveOrg`, `ErrOrgMismatch`, `ErrRBACDisabled`.
- New `admin` subpackage: RFC 7807 `Write` helper, `Problem` type, keyset
  cursor `EncodeCursor` / `DecodeCursor` codec, reserved problem code
  constants.
- Migrations 0009 (rbac) and 0010 (audit) added under
  `storage/postgres/migrations/`.

### Tradeoffs documented

- Audit writes are async; backpressure drops events with
  `Stats.AuditDropped` incremented. Block-on-backpressure would degrade
  authentication latency under spikes; this is the documented choice.
- Audit insert failures are not retried; `Stats.AuditFailed` is the ops
  signal. A persistent retry queue is an order of magnitude more
  complexity than v1.0 wants to absorb; SOC 2 evidence is better served
  by an external audit sink (planned for v1.x).
- No wildcard permissions in v1.0 (planned for v1.1); the catalog is a
  closed set so the permission check is a single set membership.
- ABAC, hierarchical roles, and time-bound permissions are explicitly
  deferred to v1.x.

### Migrating from v0.7

- `Config.AuditHook` and the synchronous `AuditEvent` shape are removed.
  Set `Config.Audit = &AuditConfig{}` to enable the async writer; existing
  no-op deployments leave it nil and see no behavior change.
- `Storage` gains 16 new methods (14 RBAC + 2 audit). Custom adapters
  built on top of `memory` or `postgres` keep working; in-tree custom
  implementations must implement the new methods. Per the new
  `Storage`-extension rule (STABILITY.md), v1.x will introduce future
  persistence operations behind optional interfaces detected via type
  assertion so this kind of break does not happen again.

## [0.7.0] - 2026-06-20

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

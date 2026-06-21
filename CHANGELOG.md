# Changelog

All notable changes to theauth-go are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) from v1.0 forward.

## [Unreleased]

### Security (audit 2026-06-20)

- H1: POST `/oauth/register` Bearer gate now validates the supplied token
  against `AuthorizationServerConfig.RegistrationTokens` under
  `crypto/subtle.ConstantTimeCompare` against pre-hashed sha256 digests.
  The legacy "any non-empty bearer is accepted" behavior is gone. Empty
  and unknown bearers return 401 access_denied. When `RegistrationTokens`
  is empty and `AllowAnonymousRegistration` is false (the default and
  production-recommended state), all registration requests are denied.
- H2: POST `/oauth/register` is now rate limited per source IP. The cap
  defaults to 1 req/min when `AllowAnonymousRegistration` is true (the
  documented public-MCP profile) and 5 req/min otherwise. Operators can
  override via the new
  `AuthorizationServerConfig.RegistrationRateLimitPerMinute` field;
  negative values disable the cap entirely.
- H3: organization-scoped delegation admin (POST
  `/admin/v1/organizations/{orgID}/delegations`) now verifies that
  `body.userId` is a member of the calling admin's organization before
  creating the grant. Cross-org targets return 403 problem+json
  (`admin.user_not_in_org`). Previously the storage row could name any
  user system-wide, which the introspection lookup would honor because
  the per-grant query does not filter by organization.
- H4: `X-Forwarded-For` is no longer trusted by default. The new
  `Config.TrustedProxies []netip.Prefix` field gates XFF: the header is
  consulted only when the incoming `r.RemoteAddr` is inside one of the
  configured prefixes. The legacy behavior (XFF honored unconditionally)
  is gone; existing deployments behind a reverse proxy must list the
  proxy's network explicitly. Operators on a direct public-internet bind
  inherit the safe default automatically.
- M2: `AddOrganizationMember` now refuses to demote the last owner of an
  organization. The upsert path runs the same `ErrLastOwner` guard as
  `RemoveOrganizationMember`. Fresh additions and promotions to owner
  remain unaffected.
- M6: the email + password signin path pays the Argon2id verify cost on
  the user-not-found and password-empty branches by verifying against a
  fixed dummy PHC hash synthesized once at `New` time. Response time no
  longer distinguishes registered from unregistered emails.

Deferred to follow-up PRs: M1 (SCIM cross-tenant email fallback), M3
(SecureCookie default), M4 (JWKS rotation transaction), M5 (mcpresource
missing-introspection startup warning), L1-L5, I1-I7.

### Added in v2.0 phase 5 + 6 (targeted for `v2.0.0`)

- New separately importable Go module: `github.com/glincker/theauth-go/mcpresource`.
  Zero dependencies outside the standard library: a consumer importing the
  package does not transitively pull theauth core or the storage adapters.
  Public surface: `Validator`, `Principal`, `Option`, `New`,
  `PrincipalFromContext`, `WithJWKS`, `WithIntrospection`, `WithCacheTTL`,
  `WithHTTPClient`, `WithClockSkew`, `(*Validator).Middleware`,
  `(*Validator).Principal`. Validates JWT signature against a cached JWKS
  (refreshes on kid miss and at the configured cache TTL), enforces the
  audience claim against the configured resource URI, checks expiry, nbf,
  and iat with a 60 second skew tolerance by default, and walks the RFC 8693
  `act` chain via the AS introspection endpoint so revocations propagate
  inside the configured cache window. On any failure the middleware emits
  HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token",
  resource_metadata="..."` per RFC 6750 + RFC 9728.
- RFC 9728 OAuth 2.0 Protected Resource Metadata: the AS exposes
  `GET /.well-known/oauth-protected-resource` (bare path returns the first
  configured resource) and `GET /.well-known/oauth-protected-resource/{path}`
  (per-resource discovery for multi-resource deployments). The document
  carries `resource`, `authorization_servers`, `bearer_methods_supported`,
  plus `scopes_supported`, `resource_name`, `jwks_uri`, and
  `resource_signing_alg_values_supported`.
- Organization-scoped admin UX under `/admin/v1/organizations/{orgID}`:
  `GET/POST/PATCH/DELETE /agents` and
  `GET/POST/DELETE /delegations`. Gated by the new seeded permissions
  `agents:admin` and `delegations:admin`; both are added to the owner and
  admin default org roles.
- End-user self-service UX under `/account` (enabled via
  `Config.AccountUX`): `GET/POST /agents`, `DELETE /agents/{id}`,
  `GET/POST /delegations`, `POST /delegations/{id}/revoke`. Session-cookie
  gated; cross-user calls return 404 to avoid leaking record existence.
- New seeded RBAC permissions: `agents:admin`, `delegations:admin`.
  Existing consumers see the additional permissions on the next
  `SeedPermissions` call; downstream role definitions that did not pre-grant
  them stay valid (catalog only grows).
- New error sentinels: `ErrAccountUXRequiresAgents`.
- Example `examples/mcp-server/`: standalone runnable demo of the
  mcpresource middleware on a tiny chi server. Shows the one-import claim:
  middleware wiring plus principal extraction in roughly ten lines of Go.
- Audit emission additions: every admin and account mutation emits the same
  events used by the service layer (`agent.created`, `agent.suspended`,
  `agent.resumed`, `agent.revoked`, `agent_credential.minted`,
  `agent_credential.revoked`, `delegation.granted`, `delegation.revoked`).
  No new action names introduced in this PR; the v2.0 phase 3 + 4 catalog
  remains the source of truth.

### v2.0 capability summary

- Phase 1 + 2 (`v2.0.0-alpha.1`): OAuth 2.1 Authorization Server core.
  `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`,
  `/oauth/register`, `/oauth/jwks`, `/.well-known/oauth-authorization-server`.
  RFC 9068 EdDSA JWT access tokens. RFC 8707 mandatory audience binding.
  PKCE S256 mandatory. RFC 9700 refresh rotation with family revocation.
  RFC 7591 dynamic client registration.
- Phase 3 + 4 (`v2.0.0-alpha.2`): agent identity and delegation chains.
  Agents (user or org owned) with one-shot client secrets. Delegation grants
  per `(user, agent, resource)`. `client_credentials` grant for agent
  self-tokens. RFC 8693 token-exchange grant with strict scope narrowing,
  strict duration tightening, and a hard chain-depth cap of 3.
  Introspection walks the actor chain on every call.
- Phase 5 + 6 (`v2.0.0`): the consumption side and the operator surface.
  `mcpresource` SDK for MCP servers. RFC 9728 protected-resource metadata.
  Admin and end-user routes for agent and delegation lifecycle.

### Added in v2.0 phase 3 + 4 (released as `v2.0.0-alpha.2`)

- Agents: `Agent`, `AgentCredential`, `AgentOwner`, `CreateAgentInput`,
  `AgentSecret` models. `CreateAgent`, `MintAgentCredential`,
  `RotateAgentSecret`, `ListAgentsByOwner`, `GetAgent`, `SuspendAgent`,
  `ResumeAgent`, `RevokeAgent` service methods. Agent credential kinds:
  `secret` (Argon2id-hashed), `x509`, `jwk`. The X.509 and JWK kinds return
  `ErrNotImplemented` in this phase so callers see a typed error.
- Delegations: `DelegationGrant`, `GrantDelegationInput` models.
  `GrantDelegation`, `ListDelegationsForUser`, `ListDelegationsForAgent`,
  `RevokeDelegation` service methods. Uniqueness on `(user_id, agent_id,
  resource)` enforced at the database layer. Revoking a grant invalidates
  every derived token at the next introspection refresh.
- Grants on `/oauth/token`:
  - `client_credentials` mints an agent self-token (`sub=agent:<id>`,
    `aud` bound to the supplied resource).
  - `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) accepts a
    user (or agent) `subject_token` plus an agent `actor_token`, looks up
    the matching delegation grant, and mints a new JWT with the nested
    `act` chain (RFC 8693 section 4.1). Chain depth is capped at 3; deeper
    chains are rejected with `invalid_request` "actor chain depth exceeded".
- Introspection now walks the full `act` chain on every call and re-checks
  the delegation grant. Any inactive actor or revoked grant flips
  `active=false`, even on a cache hit.
- AS metadata advertises `client_credentials` and the token-exchange URN in
  `grant_types_supported` whenever `Config.AgentIdentity` is configured.
- Audit emissions added: `agent.created`, `agent.suspended`, `agent.resumed`,
  `agent.revoked`, `agent_credential.minted`, `agent_credential.revoked`,
  `agent.token_minted`, `delegation.granted`, `delegation.revoked`,
  `token.exchanged`.
- Migrations: `0012_agents.up.sql` (agents + agent_credentials),
  `0013_delegations.up.sql` (delegation_grants + audit_events.actor_agent_id).
  Down migrations included.
- Storage interface: `OAuthServerStorage` extended with agent + delegation
  methods. v1.0 root `Storage` interface unchanged. Both in-tree adapters
  (memory + postgres) implement the new methods.
- Errors: `ErrAgentNotFound`, `ErrAgentInactive`, `ErrDelegationNotFound`,
  `ErrDelegationRevoked`, `ErrChainDepthExceeded`, `ErrSubjectTokenInvalid`,
  `ErrActorTokenInvalid`, `ErrNotImplemented`, `ErrAgentRequiresAS`,
  `ErrAgentChainDepthTooHigh`.

### Added in v2.0 phase 1 + 2 (released as `v2.0.0-alpha.1`)

- OAuth 2.1 Authorization Server with `/.well-known/oauth-authorization-server`,
  `/oauth/authorize`, `/oauth/token` (authorization_code + refresh_token),
  `/oauth/revoke`, `/oauth/introspect`, `/oauth/register` (RFC 7591 dynamic
  client registration), `/oauth/jwks` (Ed25519, 30 day rotation). Mandatory
  PKCE S256; mandatory RFC 8707 resource binding; RFC 9068 JWT access
  tokens; RFC 9700 refresh-token rotation with family revocation.
- New config: `AuthorizationServer *AuthorizationServerConfig`. New
  storage extension interface `OAuthServerStorage`. Migrations 0011
  (oauth_clients + authorization_codes + refresh_tokens) and 0014
  (jwks_keys); 0012 / 0013 reserved as placeholders for phase 3 + 4.

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

# Changelog

All notable changes to theauth-go are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) from v1.0 forward.

## [Unreleased]

## [2.1.0] - 2026-06-21

Internal architecture reorganization plus the v2.0 security audit followups.
**The public API is byte-stable with v2.0**: every exported type, function,
and method on `*theauth.TheAuth` keeps the same identifier, signature, and
method set. Downstream consumers compile unchanged. Anyone relying on
unexported symbols via `//go:linkname` or unsafe reflection may break (we
deleted several dead unexported root methods and consolidated forwarders).

### Internal package reorganization (PRs #20 through #28)

The 1.9k-line monolithic root grew to 49 non-test root files at v2.0; PRs
#20 through #28 extracted feature-by-feature implementations into
`internal/<flow>` subpackages while the root kept the public surface as
thin forwarders. PR G (this release) collapsed the remaining one-line
forwarders into four grouped files and removed the dead bridges that
earlier extractions left behind.

- New internal packages added across the refactor: `internal/models`,
  `internal/as`, `internal/as/handlers`, `internal/agent`,
  `internal/agent/handlers`, `internal/delegation`, `internal/session`,
  `internal/password`, `internal/password/handlers`, `internal/totp`,
  `internal/totp/handlers`, `internal/webauthn`, `internal/webauthn/handlers`,
  `internal/magiclink`, `internal/oauth/handlers`, `internal/saml`,
  `internal/saml/handlers`, `internal/scim`, `internal/scim/handlers`,
  `internal/organizations`, `internal/organizations/handlers`,
  `internal/rbac`, `internal/audit`, `internal/account/handlers`,
  `internal/admin/handlers`, `internal/clientauthcache`,
  `internal/jwt`, `internal/chain`, `internal/httpx`, `internal/wavt`,
  `internal/ulid`, `internal/bench`, `internal/samltest`.
- Root non-test `.go` file count: 49 (v2.0) to 28 (v2.1). Public surface
  unchanged.

### Dead code purge (PR G)

PR G deleted seven unused unexported root methods that lost their last
in-tree caller during PRs B through F. Every one was forwarded to a
`*as.Service` or `*<flow>.Service` method that handler packages now reach
directly. None were on the public surface; consumers are unaffected.

- `(*TheAuth).currentSigningKey` (was in `jwks.go`)
- `(*TheAuth).publicKeyByKID` (was in `jwks.go`)
- `(*TheAuth).invalidateClientAuthCache` (was in `as.go`)
- `(*TheAuth).agentBySubjectClaim` (was in `service_agent.go`); the
  `AgentLookup` adapter wired in `theauth.New` now points at
  `a.agentSvc.AgentBySubjectClaim` directly.
- `(*TheAuth).authenticateClient` (was in `service_token.go`)
- `(*TheAuth).finishRegistrationFromRequest` (was in
  `service_webauthn.go`); every handler now wraps the body in
  `http.MaxBytesReader` itself.
- `(*TheAuth).finishLoginFromRequest` (was in `service_webauthn.go`)

### Forwarder consolidation (PR G)

Twenty-one `service_*.go` forwarder files became three grouped files plus
three substantive service files preserved as-is (because they still hold
local logic, not just one-line thunks).

- `forwarders_identity.go`: session, magic-link, password, TOTP,
  WebAuthn, audit.
- `forwarders_oauth.go`: DCR, introspect, revoke, token, token v3 / v4
  grants, AS metadata, protected-resource metadata, authorize.
- `forwarders_enterprise.go`: SCIM, organizations, RBAC, delegation.
- Retained: `service_oauth.go` (OAuth state cache + GC + provider flow),
  `service_agent.go` (`validateAgentConfig` plus the agent CRUD
  forwarders), `service_saml.go` (`toInternal` adapter plus SAML
  forwarders).

Twelve root `handlers_*.go` files became eight: the five thinnest mount
forwarders (oauth, password, totp, webauthn, oauth_server) collapsed
into `mounts_extracted.go`; the six handler files that carry substantive
service adapters (`handlers_account.go`, `handlers_admin.go`,
`handlers_admin_agents.go`, `handlers_organizations.go`,
`handlers_saml.go`, `handlers_scim.go`) plus the top-level `handlers.go`
stay separate.

`errors_v20.go` merged into `errors.go`; `models_v20.go` merged into
`models.go`.

### Security (audit 2026-06-20, shipped in PR #17)

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
  creating the grant.
- H4: `X-Forwarded-For` is no longer trusted by default. The new
  `Config.TrustedProxies []netip.Prefix` field gates XFF: the header is
  consulted only when the incoming `r.RemoteAddr` is inside one of the
  configured prefixes.
- M2: `AddOrganizationMember` now refuses to demote the last owner of an
  organization.
- M6: the email + password signin path pays the Argon2id verify cost on
  the user-not-found and password-empty branches by verifying against a
  fixed dummy PHC hash synthesized once at `New` time.

### Reliability (PR #18)

- Closed the handleToken / SCIM PATCH / end-to-end AS to mcpresource
  reliability gaps surfaced by the 2026-06 test audit.

### Performance (PR #19)

- `clientauthcache` interposes between the AS handlers and the Argon2id
  client_secret verifier. First verification pays the Argon2id cost; every
  subsequent verification of the same `(client_id, secret_hash)` pair is
  served from the cache until the secret rotates or the entry ages out.
- JWKS key cache: the AES-decrypted Ed25519 private key is decrypted once
  per signing key version (rotation refreshes it) and stashed on
  `*as.Service`. Cold path is unchanged; hot path drops one AES decrypt
  per JWT mint.
- `mcpresource` validator switched from `sync.Mutex` to `sync.RWMutex` on
  the JWKS + introspection caches so concurrent reads no longer serialize.

### Removed in PR G

- Seven unused unexported methods on `*TheAuth` (see "Dead code purge"
  above).
- Twenty-one `service_*.go` files merged into three `forwarders_*.go`
  files (see "Forwarder consolidation").
- Five `handlers_*.go` files merged into one `mounts_extracted.go`.
- `errors_v20.go` merged into `errors.go`.
- `models_v20.go` merged into `models.go`.

### Deferred from the 2026-06-20 audit

Tracked as follow-up issues: M1 (SCIM cross-tenant email fallback), M3
(SecureCookie default), M4 (JWKS rotation transaction), M5 (mcpresource
missing-introspection startup warning), L1-L5, I1-I7.

## [2.0.0] - 2026-06-20

v2.0 ships the OAuth 2.1 Authorization Server, agent identity and
delegation chains (RFC 8693), and the `mcpresource` validator SDK for MCP
servers. Three alpha tags shipped phases incrementally
(`v2.0.0-alpha.1` through `v2.0.0-alpha.3`); `v2.0.0` consolidated them.

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

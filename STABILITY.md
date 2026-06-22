# theauth-go API stability

This document captures what counts as the public API of theauth-go and what
guarantees it carries. Starting with v1.0 the project follows
[Semantic Versioning](https://semver.org/) strictly: any change to a stable
symbol's signature, name, or documented behavior contract requires a v2.0
release. Adding new exported symbols, new optional `Config` fields, or new
methods on `*TheAuth` is non-breaking. Deprecations are announced one minor
version before removal with a `// Deprecated:` godoc line.

## Stable packages (v1.0)

- `github.com/glincker/theauth-go`
- `github.com/glincker/theauth-go/crypto`
- `github.com/glincker/theauth-go/email`
- `github.com/glincker/theauth-go/provider`
- `github.com/glincker/theauth-go/provider/github`
- `github.com/glincker/theauth-go/provider/google`
- `github.com/glincker/theauth-go/provider/microsoft`
- `github.com/glincker/theauth-go/provider/discord`
- `github.com/glincker/theauth-go/storage`
- `github.com/glincker/theauth-go/storage/memory`
- `github.com/glincker/theauth-go/storage/postgres`
- `github.com/glincker/theauth-go/admin`

## Stable packages (v2.0 additions)

The v1.0 surface above is unchanged. v2.0 adds the following packages, each
covered by the same SemVer guarantees from this point forward.

- `github.com/glincker/theauth-go/mcpresource` (separately importable as a
  zero-dependency Go module: a consumer pulling this package does NOT
  transitively pull theauth core or the storage adapters).

## Stable surface

### Root package: `github.com/glincker/theauth-go`

**Core types**: `TheAuth`, `Config`, `Storage`, `Provider`, `ProviderToken`,
`ProviderUser`, `User`, `Session`, `MagicLink`, `PasswordResetToken`,
`OAuthAccount`, `WebAuthnCredential`, `TOTPSecret`, `RecoveryCode`,
`SAMLConnection`, `SAMLIdentity`, `SAMLAttributeMap`, `SCIMToken`,
`Organization`, `OrganizationMember`, `Group`, `SCIMUserFilter`,
`SCIMGroupFilter`, `EnrollTOTPResult`, `SigninStep`, `TheAuthError`, `ULID`,
`Role`, `Permission`, `UserRole`, `AuditEvent`, `TargetRef`, `AuditQuery`,
`AuditMetadata`, `Stats`.

**Config subtypes**: `WebAuthnConfig`, `TOTPConfig`, `OrganizationsConfig`,
`SAMLConfig`, `SCIMConfig`, `RBACConfig`, `RoleSeed`, `AuditConfig`,
`AdminConfig`.

**Constructors and lifecycle**: `New`, `NewError`, `(*TheAuth).Start`,
`(*TheAuth).Close`, `(*TheAuth).Mount`, `(*TheAuth).Stats`.

**Auth flows**: `(*TheAuth).SignUp` (via service entry points),
`(*TheAuth).BeginPasskeyRegistration`, `FinishPasskeyRegistration`,
`BeginPasskeyLogin`, `FinishPasskeyLogin`, `BeginTOTPEnrollment`,
`FinishTOTPEnrollment`, `VerifyTOTP`, `ConsumeRecoveryCode`,
`IssuePending2FA`. Service entry points reachable via the HTTP layer
mounted by `Mount` are also stable; signatures of the unexported handlers
themselves are not part of the public contract.

**RBAC (v1.0)**: `(*TheAuth).SeedPermissions`,
`SeedOrganizationRoles`, `PermissionsForUser`, `HasPermission`, `GrantRole`,
`RevokeRole`, `CreateRole`, `UpdateRole`, `DeleteRole`,
`(*TheAuth).RequirePermission`. Plus the permission name constants
(`PermissionBillingRead`, `PermissionBillingWrite`, `PermissionBillingAdmin`,
`PermissionUsersRead`, `PermissionUsersInvite`, `PermissionUsersAdmin`,
`PermissionRolesRead`, `PermissionRolesAdmin`, `PermissionAuditRead`,
`PermissionSAMLAdmin`, `PermissionSCIMAdmin`, `PermissionSessionsRevoke`),
the seed helpers `SeededPermissions` and `DefaultRoleSeeds`, and the
constant `SystemRoleSuperAdmin`.

**Audit (v1.0)**: `(*TheAuth).EmitAudit`, `(*TheAuth).QueryAudit`,
`DefaultRedactor`, `SeededSecretKeys`, `HashEmailForAudit`,
`WithAuditMetadata`. Action strings for the canonical catalog are not
exported as constants, but the spelling of every emitted action listed in
docs/audit_catalog.md is part of the v1.0 stability commitment: existing
actions will keep their name and target shape through every minor release.

**Middleware**: `(*TheAuth).Authn`, `(*TheAuth).RequireAuth`,
`(*TheAuth).RequirePendingOrFull`, `(*TheAuth).RequirePermission`,
`(*TheAuth).RateLimitByIP`, `(*TheAuth).RateLimitByEmail`.

**Errors**: `ErrInvalidToken`, `ErrSessionExpired`, `ErrUserNotFound`,
`ErrMagicLinkExpired`, `ErrMagicLinkUsed`, `ErrEmailNotVerified`,
`ErrStorageNotFound`, `ErrReplayDetected`, `ErrAlreadyEnrolled`,
`ErrSCIMRequiresOrganizations`, `ErrSAMLRequiresOrganizations`,
`ErrSAMLUnsignedAssertion`, `ErrSAMLMissingEmail`, `ErrSAMLInvalidAssertion`,
`ErrLastOwner`, `ErrUnsupportedFilter`, `ErrSlugTaken`,
`ErrAdminRequiresRBAC`, `ErrForbidden`, `ErrUnknownPermission`,
`ErrRoleInUse`, `ErrNoActiveOrg`, `ErrOrgMismatch`, `ErrRBACDisabled`.

**Error codes**: `CodeWeakPassword`, `CodeEmailTaken`,
`CodeInvalidCredentials`, `CodeRateLimited`, `CodePasswordResetExpired`,
`CodePasswordResetInvalid`, `CodeTOTPRequired`, `CodeInvalidTOTP`,
`CodeAlreadyEnrolled`, `CodeWebAuthn`.

**Auth level constants**: `AuthLevelFull`, `AuthLevelPending2FA`.

**Signin step constants**: `SigninStepFull`, `SigninStepTOTPRequired`.

**Tunables**: `MinPasswordLength`, `PasswordResetTTL`.

**Helpers**: `UserFromContext`, `SessionFromContext`,
`DefaultSAMLAttributeMap`.

### Subpackage: `crypto`

- Constants: `AESKeyLen`.
- Functions: `Encrypt`, `Decrypt`, `NewToken`, `HashToken`, `HashPassword`,
  `VerifyPassword`, `NewCodeVerifier`, `CodeChallenge`,
  `GenerateRecoveryCode`, `HashRecoveryCode`, `VerifyRecoveryCode`.
- Errors: `ErrInvalidKeyLength`, `ErrCiphertextTooShort`,
  `ErrInvalidPasswordHash`.

### Subpackage: `email`

- Interface: `Sender`.
- Type: `Noop`.

### Subpackage: `storage`

- Re-export of root `Storage` interface plus `ErrNotFound` sentinel.

### Subpackages: `storage/memory`, `storage/postgres`

- Constructor `New` and the returned `*Store` value satisfy
  `theauth.Storage`.

### Subpackage: `admin`

- Helper functions: `Write`, `EncodeCursor`, `DecodeCursor`.
- Type: `Problem`.
- Constants: `ProblemTypeBase`, plus the `Code*` problem code constants
  (`CodeForbidden`, `CodeOrgMismatch`, `CodeNoActiveOrg`, `CodeRoleInUse`,
  `CodeUnknownPermission`, `CodeBadCursor`, `CodeUserNotInOrg`,
  `CodeValidationInvalid`, `CodeNotFound`, `CodeInternal`,
  `CodeUnauthorized`, `CodeUnsupportedAction`).

### Subpackages: `provider/github`, `provider/google`, `provider/microsoft`, `provider/discord`

- Each exposes a `Config` struct and a `New(Config) theauth.Provider`
  constructor.

### Subpackages added in v2.2: `provider/facebook`, `provider/slack`, `provider/gitlab`, `provider/bitbucket`, `provider/twitch`, `provider/linkedin`, `provider/x`, `provider/apple`

- Each exposes a `Config` struct and a `New(Config) theauth.Provider`
  constructor, following the same contract as the v1.0 provider subpackages.
- `provider/gitlab` additionally accepts a `BaseURL` field for self-hosted
  GitLab instances; defaults to https://gitlab.com.
- `provider/apple` accepts `TeamID`, `KeyID`, `PrivateKey`, and `BundleID`
  fields. The `PrivateKey` field is the ECDSA P-256 key from an Apple .p8 file.
  `ExchangeCode` mints a short-lived ES256 JWT client secret on each call.
- `provider/x` requires PKCE (code_challenge_method=S256) for all flows, per
  the X OAuth 2.0 vendor requirement. `ExchangeCode` returns an error if
  `codeVerifier` is empty.
- All eight new providers default to PKCE enabled.

### What is NOT public

- Anything under `internal/`. The Go toolchain enforces this; listed here
  for completeness.
- Anything under `examples/`. Examples may be rewritten or removed at any
  time.
- Test helpers in `*_test.go` files including `export_test.go` symbols.
  Those exist for our own tests and are not importable outside the module.
- The audit writer internals (channel sizing strategy, goroutine
  scheduling, batch SQL shape). Only the contract described under
  `Stats` and `EmitAudit` semantics is stable.

## Special rule: the `Storage` interface

Adding a method to `Storage` is a breaking change for everyone who
implements the interface. The v1.0 release closes the door on that
particular kind of breakage: new persistence operations land behind a
separate optional interface (for example `StorageWithSessionList`) and the
library uses a type assertion to detect support at runtime. The base
`Storage` interface only grows in a v2.0 release.

## Special rule: database migrations

Postgres migrations under `storage/postgres/migrations/` are append-only.
A renamed column ships as a new migration that adds the new column and (in
a later release) removes the old one. This protects deployments that run
migrations on rolling restarts.

## Special rule: audit table append-only

The `audit_events` table is append-only by contract. Storage adapters MUST
NOT expose UPDATE or DELETE methods for audit rows; the `Storage`
interface deliberately offers only `InsertAuditEvents` and
`QueryAuditEvents`. Operators wanting tamper-evidence should layer Merkle
signing on top; native signing is on the v1.x roadmap.

## Special rule: `Stats` counters

The four counters declared in v1.0 (`AuditEmitted`, `AuditWritten`,
`AuditDropped`, `AuditFailed`) are stable in name and meaning. Adding new
fields to `Stats` is allowed and non-breaking; renaming or changing the
semantics of an existing field is a v2.0 break.

## Deprecations carried into v1.0

None. The v0.7 audit and the v1.0 review both found no symbols warranting
a `// Deprecated:` marker before the v1.0 cut.

## v2.0 surface added

Every entry below is a stability commitment at v2.0. The entries are
additive: they do not rename, remove, or change the semantics of any v1.0
symbol. Consumers who do not configure `AuthorizationServer`, `AgentIdentity`,
or `AccountUX` continue to see the v1.0 surface unchanged.

### Root package (v2.0 additions)

- Types: `AuthorizationServerConfig`, `AgentConfig`, `ProtectedResource`,
  `ProtectedResourceMetadata`, `ASMetadata`, `ClientOwner`, `OAuthClient`,
  `AuthorizationCode`, `RefreshToken`, `JWKSKey`, `Agent`, `AgentOwner`,
  `AgentCredential`, `AgentSecret`, `CreateAgentInput`, `DelegationGrant`,
  `GrantDelegationInput`, `ActorClaim`, `IntrospectionResponse`,
  `TokenRequest`, `TokenResponse`, `TokenExchangeRequest`,
  `AuthorizeRequest`, `ClientRegistrationRequest`.

#### Security audit additions (2026-06-20, additive only)

- `Config.TrustedProxies []netip.Prefix`: allowlist of reverse-proxy
  prefixes whose `X-Forwarded-For` header is trusted by the rate
  limiter. Default empty slice (no XFF trust). Existing deployments
  that depend on XFF must opt in explicitly.
- `AuthorizationServerConfig.RegistrationTokens []string`: initial
  access tokens accepted by POST `/oauth/register` when DCR is bearer
  gated. Hashed at `New` time; constant-time compare on the wire.
  Default empty slice, which combined with the default
  `AllowAnonymousRegistration: false` denies all registration.
- `AuthorizationServerConfig.RegistrationRateLimitPerMinute int`:
  per-IP per-minute cap on POST `/oauth/register`. Defaults to 1 when
  `AllowAnonymousRegistration` is true and 5 otherwise. Set to a
  negative value to disable the cap.
- Constructors and lifecycle: existing `New` accepts new optional
  `Config.AuthorizationServer`, `Config.AgentIdentity`, `Config.AccountUX`
  fields; existing `Mount` automatically mounts the v2.0 routes when those
  fields are set.
- New methods on `*TheAuth`: `CreateAgent`, `MintAgentCredential`,
  `RotateAgentSecret`, `ListAgentsByOwner`, `GetAgent`, `SuspendAgent`,
  `ResumeAgent`, `RevokeAgent`, `GrantDelegation`,
  `ListDelegationsForUser`, `ListDelegationsForAgent`, `RevokeDelegation`,
  `StartAuthorize`, `ExchangeAuthorizationCode`, `RefreshAccessToken`,
  `ClientCredentialsToken`, `ExchangeToken`, `RevokeToken`,
  `IntrospectToken`, `RegisterClient`, `RotateSigningKey`,
  `ASMetadataDoc`, `ProtectedResourceMetadataDoc`.
- Storage extension: `OAuthServerStorage` interface (root `Storage`
  remains unchanged; AS-enabled deployments require an adapter that
  satisfies both).
- New permission names: `agents:admin`, `delegations:admin`. Owner and
  admin default org roles include both.
- New error sentinels (additive): `ErrASIssuerRequired`,
  `ErrASRequiresEncryptionKey`, `ErrASUnsupportedAlg`,
  `ErrOAuthInvalidRequest`, `ErrOAuthInvalidClient`, `ErrOAuthInvalidGrant`,
  `ErrOAuthInvalidScope`, `ErrOAuthUnsupportedGrantType`,
  `ErrOAuthUnsupportedResponseType`, `ErrOAuthInvalidResource`,
  `ErrOAuthRegistrationDenied`, `ErrOAuthRedirectURIMismatch`,
  `ErrOAuthPKCEMismatch`, `ErrOAuthAudienceMismatch`, `ErrNotImplemented`,
  `ErrAgentNotFound`, `ErrAgentInactive`, `ErrDelegationNotFound`,
  `ErrDelegationRevoked`, `ErrChainDepthExceeded`, `ErrSubjectTokenInvalid`,
  `ErrActorTokenInvalid`, `ErrAgentRequiresAS`, `ErrAgentChainDepthTooHigh`,
  `ErrAccountUXRequiresAgents`, `ErrStorageMissingOAuthMethods`.

### Subpackage `mcpresource` (new in v2.0)

- Types: `Validator`, `Principal`, `Option`.
- Functions: `New`, `PrincipalFromContext`.
- Options: `WithJWKS`, `WithIntrospection`, `WithCacheTTL`,
  `WithHTTPClient`, `WithClockSkew`.
- Methods: `(*Validator).Middleware`, `(*Validator).Principal`,
  `(*Validator).ResourceURI`, `(*Validator).CacheTTL`.

### HTTP surface (mounted by `Mount` when configured)

- `GET /.well-known/oauth-authorization-server` (RFC 8414).
- `GET /.well-known/oauth-protected-resource` (RFC 9728, default resource).
- `GET /.well-known/oauth-protected-resource/{path}` (RFC 9728, per-resource).
- `GET /oauth/jwks` (RFC 7517).
- `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke`,
  `POST /oauth/introspect`, `POST /oauth/register`.
- `/admin/v1/organizations/{orgID}/agents` and
  `/admin/v1/organizations/{orgID}/delegations` (RBAC-gated).
- `/account/agents` and `/account/delegations` (session-gated, when
  `Config.AccountUX` is true).

### What is NOT public in v2.0

- `internal/jwt`, `internal/chain`, `internal/ulid` remain internal.
- The HTTP error body wire shape for `application/problem+json` follows
  RFC 7807; the `code` extension namespace is reserved by this library and
  may grow with new codes in additive minor releases.

## What changes without a major bump

- Bug fixes that preserve documented behavior.
- Performance improvements that preserve observable outputs.
- New optional `Config` fields with backward-compatible zero values.
- New methods on `*TheAuth` that do not conflict with existing ones.
- New error sentinels and codes (callers must not switch exhaustively).
- New migrations that add tables or columns without renaming or removing
  existing ones.
- New audit event actions (existing ones keep their name and target shape).
- New `Stats` fields (existing ones keep their name and meaning).

## What requires a major bump

- Removing or renaming any stable symbol.
- Changing the signature of any exported function or method.
- Adding a required method to `Storage` (see the special rule).
- Removing a column or renaming it destructively (migrations stay
  append-only).
- Changing the semantics of an existing `Stats` field.
- Adding UPDATE or DELETE to the audit interface.

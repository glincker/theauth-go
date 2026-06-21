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

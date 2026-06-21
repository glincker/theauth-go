# theauth-go API stability

This document captures what counts as the public API of theauth-go and what
guarantees it carries. The project follows [Semantic
Versioning](https://semver.org/) starting from v1.0.

## Stable surface (v0.6 candidate for v1.0)

The following packages and symbols are public. Anything not listed here is
implementation detail and may change in any release.

### Root package: `github.com/glincker/theauth-go`

- Types: `TheAuth`, `Config`, `Storage`, `Provider`, `ProviderToken`,
  `ProviderUser`, `User`, `Session`, `MagicLink`, `PasswordResetToken`,
  `OAuthAccount`, `WebAuthnConfig`, `TOTPConfig`, `WebAuthnCredential`,
  `TOTPSecret`, `RecoveryCode`, `EnrollTOTPResult`, `TheAuthError`,
  `ULID`, `SigninStep`.
- Constructors: `New`, `NewError`.
- Methods on `*TheAuth`: `Mount`, `Authn`, `RequireAuth`,
  `RequirePendingOrFull`, `RateLimitByIP`, `RateLimitByEmail`, `Close`,
  `IssuePending2FA`, `BeginTOTPEnrollment`, `FinishTOTPEnrollment`,
  `VerifyTOTP`, `ConsumeRecoveryCode`.
- Helpers: `UserFromContext`, `SessionFromContext`.
- Error sentinels: `ErrInvalidToken`, `ErrSessionExpired`,
  `ErrUserNotFound`, `ErrMagicLinkExpired`, `ErrMagicLinkUsed`,
  `ErrEmailNotVerified`, `ErrStorageNotFound`, `ErrReplayDetected`,
  `ErrAlreadyEnrolled`.
- Error codes: `CodeWeakPassword`, `CodeEmailTaken`,
  `CodeInvalidCredentials`, `CodeRateLimited`, `CodePasswordResetExpired`,
  `CodePasswordResetInvalid`, `CodeTOTPRequired`, `CodeInvalidTOTP`,
  `CodeAlreadyEnrolled`, `CodeWebAuthn`.
- Auth level constants: `AuthLevelFull`, `AuthLevelPending2FA`.
- Signin step constants: `SigninStepFull`, `SigninStepTOTPRequired`.
- Tunables: `MinPasswordLength`, `PasswordResetTTL`.

### Subpackage: `crypto`

- Constants: `AESKeyLen`.
- Functions: `Encrypt`, `Decrypt`, `NewToken`, `HashToken`,
  `HashPassword`, `VerifyPassword`, `NewCodeVerifier`, `CodeChallenge`,
  `GenerateRecoveryCode`, `HashRecoveryCode`, `VerifyRecoveryCode`.
- Errors: `ErrInvalidKeyLength`, `ErrCiphertextTooShort`,
  `ErrInvalidPasswordHash`.

### Subpackage: `email`

- Interface: `Sender`.
- Type: `Noop`.

### Subpackage: `storage`

- Re-export of root `Storage` interface plus `ErrNotFound` sentinel.

### Subpackages: `storage/memory`, `storage/postgres`

- Constructor `New` and the returned `*Store` value satisfy `theauth.Storage`.

### Subpackages: `provider/github`, `provider/google`, `provider/microsoft`, `provider/discord`

- Each exposes a `Config` struct and a `New(Config) theauth.Provider`
  constructor.

### What is NOT public

- Anything under `internal/`. The Go toolchain enforces this; we list it
  here for completeness.
- Anything under `examples/`. Examples may be rewritten or removed at any
  time.
- Test helpers in `*_test.go` files including `export_test.go` symbols.
  Those exist for our own tests and are not importable outside the module.

## Special rule: the `Storage` interface

Adding a method to `Storage` is a breaking change for everyone who
implements the interface (which is the supported integration pattern).
From v1.0 forward, new persistence operations land behind a separate
optional interface (for example `StorageWithRefreshTokens`) and the
library uses a type assertion to detect support at runtime. The base
`Storage` interface only grows in a major version bump.

## Special rule: database migrations

Postgres migrations under `storage/postgres/migrations/` are
append-only. A renamed column ships as a new migration that adds the new
column and (in a later release) removes the old one. This protects
deployments that run migrations on rolling restarts.

## Deprecations carried into v1.0

None. The v0.6 audit found no symbols that warrant a `// Deprecated:`
marker before the v1.0 cut. The hypothetical `Config.LegacyCookieName`
and `Config.AllowInsecureCookies` fields named in the v0.6 design
document do not exist in this tree and were not introduced.

## What changes without a major bump

- Bug fixes that preserve documented behavior.
- Performance improvements that preserve observable outputs.
- New optional `Config` fields with backward-compatible zero values.
- New methods on `*TheAuth` that do not conflict with existing ones.
- New error sentinels and codes (callers must not switch exhaustively).
- New migrations that add tables or columns without renaming or removing
  existing ones.

## What requires a major bump

- Removing or renaming any symbol listed above.
- Changing the signature of any exported function or method.
- Adding a required method to `Storage` (see the special rule).
- Removing a column or renaming it destructively (migrations stay
  append-only).

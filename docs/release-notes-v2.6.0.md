# theauth-go v2.6.0

Docs: https://docs.theauth.dev/go . Full list: [CHANGELOG.md](../CHANGELOG.md).

## Upgrade notes

- **Module path is now `github.com/glincker/theauth-go/v2`.** Update imports; the old path stays at v1.0.0. This is the first resolvable v2 tag. See the migration guide: https://docs.theauth.dev/go/migrations/to-v2-module-path
- **Login throttle is on by default.** 429 with `Retry-After`, codes `rate_limited` or `account_locked`. Tune with `Config.LoginThrottle`.
- **Errors are JSON** `{"code","message"}` instead of plain text. Status codes are unchanged.
- **TOTP verify and recovery routes rotate the session cookie.**
- **The `theauth_oauth_state` cookie value no longer equals the `state` parameter.**
- **OAuth callback refuses an email that matches an existing account** unless the provider marks it verified.
- **An https `BaseURL` now yields Secure cookies.**
- **`EncryptionKey` is required when `ProviderResolver` is set.**
- **Device-request routes need the root ability by default** (`DeviceRequestsAbility`, or `DeviceRequestsAnySignedInUser`).
- **Closed signup and `Config.Bootstrap` need `UserCountStorage`.**
- **`PasswordPolicy.AllowLegacyBcrypt` is now honored.**
- **The repository layout changed; no exported name was removed.** The module root holds 15 Go files (it held 80), feature code is in `internal/` packages and black-box tests are in `integration/`. Imports and calls are unaffected; `%T` and `reflect` print the aliased type, and `go test` on the root package no longer runs the integration suite (use `./...`).
- **CIMD fetches refuse non-public addresses** (a localhost CIMD setup needs `CIMDConfig.AllowPrivateNetworks`).
- **Authorization errors redirect only to a registered `redirect_uri`, and SAML `RelayState` is restricted** (`SAMLConfig.AllowedRelayStates`).
- Also: CSRF/Origin checks on cookie-authenticated writes (`TrustedOrigins`), 72 byte password cap, new migrations (Postgres and MySQL 0017 and 0018, SQLite 0006 to 0008).

## Highlights

- Storage capability interfaces and `Config.CoreStorage`; SQLite, Postgres and MySQL capability parity.
- `storage/sqlite` adapter (experimental).
- Scoped API tokens, RFC 8628 device grant, token self-service routes, device pending list.
- `clientauth` for CLI login, agent identity tokens (`MintAgentToken`, `RegisterAgent`), revocation watcher.
- `policy` JSON policy engine and `RequirePolicy` middleware.
- Security doctor: `Doctor`, `GET /auth/admin/doctor`, `cmd/theauth-doctor`.
- `Config.PathPrefix`, `(*TheAuth).Handler()`, `Config.ProviderResolver`, `provider/oidc`, `Config.OAuth`.
- Session management, step-up re-auth, session links, passkey policy, `AuthEventSink`.

## Security

- Login throttle and per-user lockout, TOTP replay protection, per-user MFA guess caps.
- First-run bootstrap with a one-time setup token, email canonicalization, password policy and optional HIBP check.
- OAuth login CSRF binding and verified-email account linking.
- SSRF guard on the CIMD client-metadata fetch (dial-time address check, no redirects); authorization error and SAML `RelayState` redirects validated.
- Fix: synced passkeys (backup-eligible flag) can sign in again.

## Stability

New and Experimental in this release: `storage/sqlite`, `clientauth`, `policy`, the agent identity and revocation APIs, `Doctor`, `Config.ProviderResolver`, and the new optional storage capabilities (sessions, API tokens, device codes). Only the storage capability split, `Handler()` and `Config.PathPrefix` are Stable. See [STABILITY.md](STABILITY.md).

# Roadmap

This is the living, human-readable version of what's in flight. The
authoritative record of what's shipped is [CHANGELOG.md](../CHANGELOG.md);
this file is forward-looking and gets pruned as items land.

## Shipped

The latest release is v2.7.0 (2026-10-05). [CHANGELOG.md](../CHANGELOG.md) is the
record of what shipped; its v2.7.0 entries still sit under `[Unreleased]` and
have not been moved into a dated section yet.

- **v2.7.0**: `OAuthConfig.RedirectURI` and related validation with the
  `OAuthStart` and `OAuthCallback` entry points, default logs without email
  addresses, `ResetPasswordAdmin` clearing login backoff entries,
  `WebAuthnConfig.UserHandleResolver`, and `PasswordPolicy.OnLegacyHashAccepted`
  now being invoked.
- **v2.6.0**: module path `github.com/glincker/theauth-go/v2` (the earlier v2.x
  tags never resolved through the Go toolchain), login throttle on by default,
  JSON error bodies, `Config.PathPrefix`, `Handler()`, storage capability
  interfaces with `Config.CoreStorage`, the `storage/sqlite` adapter, and the
  repository layout split into `internal/` packages. Read its upgrade notes
  before moving from v2.5.x.
- **v2.5.0**: the full `Config.LifecycleHooks` surface, the `Mount()`
  hook-bypass fix, and a batch of storage-layer correctness fixes across
  Postgres and MySQL.

## In flight

- [ ] Selective package re-exports (#79, still open) so consumers can import
      fewer symbols from the root package. The v2.6.0 aliases keep existing
      root names working but are not the selective re-exports that issue asks
      for.

## Stability hardening (in progress)

- [ ] Raise `internal/rbac` and `internal/webauthn` unit coverage further
      beyond the DeleteRole/DeleteCredential gaps closed in this pass
- [ ] **Full storage-contract-suite parity (bigger, separate effort).**
      The shared contract test suite fails against both Postgres and (now
      confirmed, not just suspected) MySQL on constraint and foreign-key
      edge cases the lenient in-memory backend doesn't enforce, plus a
      couple of correctness bugs in individual methods (e.g. JWKS key
      update on an unknown KID doesn't return `ErrNotFound`). Each backend
      needs its own investigation before the opt-in contract gates can be
      enabled by default in CI.

## Under consideration

Nothing else is committed yet. Feature requests and discussion happen in
[GitHub Discussions](https://github.com/glincker/theauth-go/discussions);
raised items get added here once there's a concrete plan.

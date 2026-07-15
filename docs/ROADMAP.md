# Roadmap

This is the living, human-readable version of what's in flight. The
authoritative record of what's shipped is [CHANGELOG.md](CHANGELOG.md);
this file is forward-looking and gets pruned as items land.

## Now (v2.5.x)

The `Config.LifecycleHooks` surface introduced in v2.5.0-rc.1 is now fully
wired: `OnSignup` (password, magic-link, OAuth callback, passkey-first-
credential, SAML), `OnSignin` (password, magic-link, OAuth callback),
`OnPasswordChange`, `OnMFAEnabled`, `OnOrgSwitch` (explicit
`SetActiveOrganization` only, not auto-provisioned personal orgs),
`OnTokenIssued` (every access-token grant), and `OnOAuthConflict`, plus
the `IssueSessionByUserID` / `LinkOAuthProviderBySession` /
`UnlinkOAuthProvider` forwarders that support custom OAuth-conflict
resolution flows.

Fixed alongside the remaining wiring: `passwordhandlers`, `totphandlers`,
and `webauthnhandlers` previously held the raw internal Service directly,
bypassing the hook-firing root forwarders entirely, so `OnSignup`/
`OnSignin`/`OnPasswordChange`/`OnMFAEnabled` never fired for consumers
using the batteries-included `a.Mount()` routes. Each package now takes a
root-backed adapter (mirroring the pattern already used correctly for
OAuth/Organizations/SAML), so hooks fire through the default `Mount()`
path too.

Remaining:

- [ ] Selective package re-exports (#79) so consumers can import fewer
      symbols from the root package

## Stability hardening (in progress)

- [x] Fix 7 confirmed Postgres/MySQL storage methods silently succeeding on
      missing-row updates instead of returning `ErrNotFound`
- [x] MySQL service container available in CI (opt-in contract gate, not
      yet enabled by default)
- [x] Dependency and static-analysis scanning (Dependabot, CodeQL)
- [x] Fix `mysql.Migrate()` against MySQL 8.4: several migrations used
      `TEXT/BLOB ... DEFAULT ''`, which 8.4 rejects outright, and the
      statement splitter dropped statements preceded by comment lines (and
      mis-split on a semicolon that happened to appear inside a comment).
      Migrations now apply cleanly end-to-end against a live MySQL 8.4
      instance.
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

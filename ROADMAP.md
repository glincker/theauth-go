# Roadmap

This is the living, human-readable version of what's in flight. The
authoritative record of what's shipped is [CHANGELOG.md](CHANGELOG.md);
this file is forward-looking and gets pruned as items land.

## Now (v2.5.x)

Continuing the `Config.LifecycleHooks` surface introduced in v2.5.0-rc.1.
Shipped so far: `OnSignup`, `OnSignin` (password, magic-link, OAuth
callback paths), `OnOAuthConflict`, plus the `IssueSessionByUserID` /
`LinkOAuthProviderBySession` / `UnlinkOAuthProvider` forwarders that
support custom OAuth-conflict resolution flows.

Remaining hook wiring, landing incrementally without API changes:

- [ ] Passkey and SAML signup paths call `OnSignup`
- [ ] `OnPasswordChange`
- [ ] `OnMFAEnabled`
- [ ] `OnTokenIssued`
- [ ] `OnOrgSwitch`
- [ ] Selective package re-exports (#79) so consumers can import fewer
      symbols from the root package

## Stability hardening (in progress)

- [x] Fix 7 confirmed Postgres/MySQL storage methods silently succeeding on
      missing-row updates instead of returning `ErrNotFound`
- [x] MySQL service container available in CI (opt-in contract gate, not
      yet enabled by default)
- [x] Dependency and static-analysis scanning (Dependabot, CodeQL)
- [ ] Raise `internal/rbac` and `internal/webauthn` unit coverage further
      beyond the DeleteRole/DeleteCredential gaps closed in this pass
- [ ] **Full storage-contract-suite parity (bigger, separate effort).**
      The shared contract test suite fails today against Postgres on
      constraint and foreign-key edge cases the lenient in-memory backend
      doesn't enforce; MySQL's status against the same suite is
      unverified. Each backend needs its own investigation before the
      opt-in contract gates can be enabled by default in CI.

## Under consideration

Nothing else is committed yet. Feature requests and discussion happen in
[GitHub Discussions](https://github.com/glincker/theauth-go/discussions);
raised items get added here once there's a concrete plan.

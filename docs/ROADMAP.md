# Roadmap

This is the living, human-readable version of what's in flight. The
authoritative record of what's shipped is [CHANGELOG.md](CHANGELOG.md);
this file is forward-looking and gets pruned as items land.

## Now (v2.5.x)

v2.5.0 is shipped (see [CHANGELOG.md](CHANGELOG.md)): the full
`Config.LifecycleHooks` surface, the `Mount()` hook-bypass fix, and a batch
of storage-layer correctness fixes across Postgres and MySQL.

- [ ] Selective package re-exports (#79) so consumers can import fewer
      symbols from the root package

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

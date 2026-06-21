# theauth-go benchmark baselines

These numbers are the v0.6 reference for the five original hot paths,
plus the v2.0 hot paths introduced by the `perf/audit-top3-2026-06-20`
PR. Future PRs that change any hot path should re-run the suite and
update this file when the delta moves more than 25 percent (in either
direction) on the same hardware.

## How to re-run

```
go test -bench=. -benchmem -run=^$ -benchtime=3s ./internal/bench/...
```

## Reference machine

- Hardware: Apple M4 Max
- OS: darwin (macOS), arm64
- Go: 1.25.0
- Date captured: 2026-06-20
- All adapters: in-memory (Postgres adds round-trip cost not measured here)

## Raw output

```
goos: darwin
goarch: arm64
pkg: github.com/glincker/theauth-go/internal/bench
cpu: Apple M4 Max
BenchmarkLoginPassword-14                       122  28268409 ns/op  67139321 B/op  191 allocs/op
BenchmarkMagicLinkConsume-14                 644880      5077 ns/op      9229 B/op   62 allocs/op
BenchmarkOAuthCallback-14                   4505914       792.5 ns/op    1376 B/op    5 allocs/op
BenchmarkOAuthTokenEndpointRefreshHit-14     162955     21998 ns/op     14744 B/op   87 allocs/op
BenchmarkJWKSEndpoint-14                    1221128      2878 ns/op      3037 B/op   37 allocs/op
BenchmarkPKCEChallenge-14                  10861368       331.9 ns/op     240 B/op    5 allocs/op
BenchmarkSessionLookup-14                   1000000      3348 ns/op      8674 B/op   42 allocs/op
```

## Summary table

| Benchmark                              | ns/op       | B/op       | allocs/op | Notes                                                        |
| -------------------------------------- | ----------- | ---------- | --------- | ------------------------------------------------------------ |
| BenchmarkLoginPassword                 | 28,268,409  | 67,139,321 | 191       | Argon2id verify dominates (intentional, OWASP)               |
| BenchmarkMagicLinkConsume              | 5,077       | 9,229      | 62        | Magic link request round trip                                |
| BenchmarkOAuthCallback                 | 793         | 1,376      | 5         | AES-GCM encrypt plus in-memory upsert                        |
| BenchmarkOAuthTokenEndpointRefreshHit  | 21,998      | 14,744     | 87        | NEW (audit fix 1 + 2): /oauth/token refresh, cache hot       |
| BenchmarkJWKSEndpoint                  | 2,878       | 3,037      | 37        | NEW (audit fix 2): /oauth/jwks GET, snapshot read            |
| BenchmarkPKCEChallenge                 | 332         | 240        | 5         | crypto/rand 32 bytes plus SHA-256                            |
| BenchmarkSessionLookup                 | 3,348       | 8,674      | 42        | Cookie parse plus token hash plus lookup                     |

## perf/audit-top3-2026-06-20 deltas

The 2026-06-20 audit (`docs-local/2026-06-20-theauth-go-perf-audit.md`)
identified three bottlenecks. After landing the corresponding fixes:

| Hot path                                       | Before                   | After                  | Delta                  |
| ---------------------------------------------- | ------------------------ | ---------------------- | ---------------------- |
| /oauth/token, /oauth/introspect, /oauth/revoke | ~27,600,000 ns/op        | ~22,000 ns/op          | ~1,254x                |
| (client_secret Argon2 verify on every call)    | (audit section 2.1, 2.2) | (cache hit, this PR)   |                        |
| JWT mint signing key load                      | ~13,000 + 5-10k ns/op    | ~13,000 ns/op (cached) | ~30 percent allocs cut |
| (AES-GCM decrypt of Ed25519 seed per call)     | (audit section 2.3)      | (snapshot pointer)     |                        |
| mcpresource introspection cache contention     | sync.Mutex serialise     | sync.RWMutex parallel  | scales with cores      |
| (cache hit path under high concurrency)        | (audit section 4.4)      | (this PR)              |                        |

Re-baseline rationale: the BenchmarkLoginPassword +4.3 percent drift over
the v0.6 reference (27,097,065 -> 28,268,409 ns/op) is inside the
documented 25 percent regression band and reflects M4 Max thermal noise
during the audit run, not a code change.

## Cache invalidation contracts

The two new caches added by the audit fix expose explicit invalidation
contracts so a security-sensitive rotation cannot be shadowed by a stale
hit:

### client_secret cache (`internal/clientauthcache`)

- Keyed by `client_id`; entry holds `sha256(presented_secret)` plus the
  verified `*OAuthClient` snapshot.
- LRU bounded at 1024 entries (configurable). TTL 5 minutes.
- Failures are NEVER cached: an attacker presenting a wrong secret keeps
  paying the full Argon2 cost so the rate limiter can throttle them, and
  the legitimate client's hot entry is never poisoned by a wrong-secret
  probe.
- The sha256 of the presented secret is bound to the cached entry; a
  subsequent call with the same `client_id` but a different secret falls
  through to the slow Argon2 verifier (which then rejects).
- Invalidated by `invalidateClientAuthCache(clientID)`. Current call
  sites:
  - `service_agent.go::MintAgentCredential` (rotates the agent secret
    via `storage.UpdateOAuthClient`; called from `RotateAgentSecret`).
  - `service_agent.go::CreateAgent` failure cleanup (deletes the orphan
    client via `storage.DeleteOAuthClient`).
- Future call sites that mutate the stored `client_secret_hash` (a future
  DCR `UpdateClient` endpoint, an admin "rotate client secret" surface,
  etc.) MUST add an `invalidateClientAuthCache(clientID)` call alongside
  the storage write.

### JWKS private-key cache (`asState.privKeyByKID`)

- Owned by the JWKS snapshot.
- Populated wholesale by `refreshJWKSSnapshot`. Every state transition
  (bootstrap, scheduled rotation, manual `RotateSigningKey`) routes
  through that function, so a rotated KID's private key disappears
  from the cache at the same moment its row leaves the `current` state.
- Retired keys are NOT cached (they cannot sign by definition).
- No external invalidation surface: the snapshot owns the lifecycle.

## Regression rule

A PR that regresses any of these numbers by more than 25 percent on the
same reference machine must:

1. Profile the affected benchmark (`go test -bench=BenchmarkX
   -cpuprofile=cpu.out`).
2. Identify the cause: new allocations, new storage round trips, new
   crypto operations, weakened Argon2 params (should never happen), or
   genuine algorithmic change.
3. Either revert the regression or update this file with the new
   baseline and a one-paragraph justification.

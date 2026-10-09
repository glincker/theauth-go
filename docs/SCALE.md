# Scale and capacity

What one theauth-go instance does against a real Postgres under concurrent
HTTP load, what limits it, and how to size it. Every number here comes from
`scripts/loadtest.sh`, which anyone can rerun. The in-memory micro-benchmarks
in [BENCHMARKS.md](BENCHMARKS.md) are the floor for CPU cost per call. This
page adds the database and concurrency.

## Test setup

| | |
| --- | --- |
| Machine | Apple M4 Max, 14 cores, 36 GiB, macOS |
| Database | Postgres 16 in Docker, on the same machine |
| Data | 100,000 users, each with one live session |
| Server | `cmd/theauth-loadtest serve`, one process, `pgxpool` |
| Client | `cmd/theauth-loadtest run`, 64 concurrent clients, 12 s per run |

Server, client and database share one laptop, so each pays for the others'
CPU, and the laptop was not idle (load average about 12 on 14 cores). Sign-in
is CPU-bound and repeated within a few percent. Anything that depends on the
database round trip varied by several times between runs, so the session path
is reported from an isolated storage benchmark instead. Each table says how it
was measured.

## Session lookup (every authenticated request)

Validating a session cookie took two sequential Postgres queries: the session
by token hash, then the user by id. The Postgres adapter now offers an
optional `SessionAndUserByTokenHash` that does both in one join, and session
validation uses it when the adapter has it.

Isolated at the storage layer, parallel across 14 cores, 20,000 sessions,
three alternating-order rounds (`BenchmarkSessionLookup`):

| Path | Per lookup | Lookups/s per process |
| --- | --- | --- |
| Two queries (before) | 58 to 67 us | 15,000 to 17,000 |
| One joined query (now) | 30 us | 33,000 |

About twice the lookups per second, and half the connection time per request.
The two paths return the same session and user, which a test checks.

Over HTTP with 100,000 sessions the whole path measured between roughly 5,000
and 30,000 requests/s across runs. That spread is the test machine (server,
load generator and database on one laptop that was also busy), not the
library, so this page does not publish an HTTP session number. Run
`scripts/loadtest.sh` on a quiet machine, ideally with the database on its
own host, and use that. The storage benchmark above is the stable figure.

Size the connection pool at least to your core count, and larger when each
request also does other database work. A pool of 4 serving 64 clients
visibly queues.

## Password sign-in (Argon2id)

`POST /auth/email-password/signin`. Argon2id at 64 MiB, 3 passes, 4 threads
is deliberately expensive, so sign-in is CPU-bound and memory-hungry.

Before the concurrency bound existed, nothing limited simultaneous hashes (single runs with the same harness, taken before the limiter was added):

| Concurrent sign-ins | Sign-ins/s | p99 | Server memory |
| --- | --- | --- | --- |
| 1 | 31 | 36 ms | 343 MB |
| 8 | 75 | 151 ms | 1.5 GB |
| 32 | 75 | 1.25 s | 4.1 GB |
| 128 | 74 | 3.8 s | 7.5 GB |

Throughput stopped at about 75 per second once the cores were busy, while
memory kept growing: each in-flight sign-in held its own 64 MiB. A burst of
logins (a morning rush, a credential-stuffing run) could take a small
container down with an out-of-memory kill.

With `PasswordPolicy.HashConcurrency` (64 clients, median of three runs):

| Bound | Sign-ins/s | p99 | Server memory |
| --- | --- | --- | --- |
| 1 | 39 | 1.9 s | 285 MB |
| 2 | 66 | 1.1 s | 350 to 480 MB |
| **3 (default here)** | **76** | **0.98 s** | **608 MB** |
| 4 | 75 | 1.0 s | 800 to 930 MB |
| 7 | 73 | 1.0 s | 1.2 to 1.4 GB |

The default, `NumCPU / 4` (3 on 14 cores), is where throughput stops
improving. Extra callers queue instead of allocating, so memory is flat and
tail latency is lower.

**Rules of thumb**

- Sign-ins per second per instance is about 5 to 6 per core.
- Peak hash memory is `HashConcurrency x 64 MiB`.
- Read capacity is set by database connections, write capacity of sign-in by
  cores. They scale independently, so scale instances for sign-in and
  Postgres connections or replicas for the session path.

## Changes this work made

- **One-query session lookup**, about 2x on the storage path (above).
  Adapters without `SessionAndUserByTokenHash` keep the two-query path.
- **Bounded hashing.** `Config.PasswordPolicy.HashConcurrency`, default
  `NumCPU / 4`, bounds simultaneous Argon2id work process-wide.

## What this does not show

- A multi-node cluster, failover, or a Postgres primary under write pressure.
- Network latency between the app and the database. Add your round trip time
  to each query: the join matters more as that grows.
- Endpoints other than session lookup and password sign-in (OAuth code flow,
  SAML, SCIM, token exchange). See BENCHMARKS.md for their CPU cost.
- Users beyond 100,000. Lookups use a unique index on the token hash, so
  cost should grow with index depth, not table size, but 10 million was not
  tested.
- An end-to-end HTTP session figure on dedicated hardware.
- Read replicas or a session cache (below).

## Running more than one instance

- The default rate limits (5 per minute per IP, 3 per minute per email) are
  **per process and in memory**. Behind a load balancer each instance counts
  alone. Enforce limits at the balancer or pass your own limiter.
- Sessions live in Postgres, so any instance can serve any request. No sticky
  routing is needed.
- Argon2id concurrency is per process: total hash memory is instances times
  the bound.

## Where the next gains are

Not built yet, in the order I would try them:

1. **Short session cache.** A few seconds of in-process caching of session
   lookups removes most database reads. The cost is that a revoked session
   stays valid for up to that TTL, so make the TTL configurable and keep it
   off by default.
2. **Read replica for lookups.** Session validation is a read. Pointing it at
   a replica keeps the primary for sign-in and writes. Replica lag has the
   same revocation tradeoff as a cache.
3. **Stateless access tokens on hot paths.** Short-lived signed tokens skip
   the database entirely, with revocation handled by expiry.
4. **Configurable Argon2id cost.** The cost is fixed at 64 MiB, 3 passes. A
   lower-memory profile trades per-hash resistance for more sign-ins per core.

## Reproduce

```
scripts/loadtest.sh            # 100,000 users
scripts/loadtest.sh 1000000    # larger
```

The script starts and removes its own Postgres container, repeats every
measurement three times, and prints each run so noise is visible. To drive
your own setup, see `cmd/theauth-loadtest/main.go`: `seed` bulk-loads users
and sessions, `serve` runs the library on Postgres, `run` generates load.
`go test ./storage/postgres -bench SessionLookup` needs `POSTGRES_TEST_URL`
and reproduces the storage figure.

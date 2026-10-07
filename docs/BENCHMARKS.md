# theauth-go Benchmark Gate

A curated benchmark suite and a regression gate (default threshold 25%) live
in `scripts/bench-gate.sh` and `benchgate/curated.txt`. The `bench` GitHub
Actions workflow runs the suite on manual dispatch and on a weekly schedule,
not on every pull request. The normal `ci` workflow does run the
`internal/bench` benchmarks on pull requests with `-benchtime=1x`, which only
checks that they still execute; it does not compare timings. See
[CI workflow](#ci-workflow) for the current limits.

This page lists no ns/op figures. Run the suite on your own hardware if you
need numbers.

## Curated benchmark list

| Benchmark | Package | Rationale |
|---|---|---|
| `BenchmarkOAuthTokenEndpointRefreshHit` | `internal/bench` | The 1254x regression source (v2.0 audit). Measures /oauth/token refresh grant with Argon2 cache warm. |
| `BenchmarkOAuthCodeFlow` | `internal/bench` | End-to-end authorization code grant: PKCE S256 verify + code consume + JWT mint + refresh insert. |
| `BenchmarkSCIMTokenAuth` | `internal/bench` | SCIM bearer authentication: sha256 hash + one storage lookup. Guards the single-round-trip perf fix. |
| `BenchmarkRateLimitReadHeavy` | root package | Rate limiter under parallel read-heavy load. Guards the shared-RLock optimisation. |
| `BenchmarkJWKSEndpoint` | `internal/bench` | JWKS endpoint: snapshot read + JSON marshal. Smoke-tests the signing-key cache. |
| `BenchmarkAuditRedactor` | `internal/bench` | Audit redactor EqualFold key matching. Guards the no-alloc-per-key optimisation. |
| `BenchmarkArgon2Hash` | `crypto` | Argon2id hash at production work factor. Catches accidental work-factor increases. |
| `BenchmarkArgon2Verify` | `crypto` | Argon2id verify at production work factor. Catches accidental work-factor increases. |
| `BenchmarkJWTSign` | `internal/jwt` | Ed25519 JWT sign. Catches algorithm changes or extra allocations. |
| `BenchmarkJWTVerify` | `internal/jwt` | Ed25519 JWT verify. Catches algorithm changes or extra allocations. |
| `BenchmarkSessionLookup` | `internal/bench` | Cookie parse + token hash + map lookup. Floor cost for every authenticated request. |
| `BenchmarkOAuthCallback` | `internal/bench` | AES-GCM encrypt + in-memory upsert. Covers the social-provider callback path. |

The authoritative list lives in `benchgate/curated.txt`. Edit that file to
add or remove benchmarks; the gate script and workflow pick it up
automatically.

## Running locally

```bash
# Full gate run (2 s per benchmark, 10 runs each -- matches CI):
./scripts/bench-gate.sh

# Quick smoke run (1 iteration only):
BENCH_TIME=1x BENCH_COUNT=1 ./scripts/bench-gate.sh

# With single-core pinning to reduce scheduler noise (Linux/macOS with taskset):
BENCH_PIN=1 ./scripts/bench-gate.sh

# Compare a feature branch against main:
git checkout main
./scripts/bench-gate.sh > /tmp/base.txt
git checkout my-feature
./scripts/bench-gate.sh > /tmp/pr.txt
benchstat /tmp/base.txt /tmp/pr.txt

# Check whether a diff file would pass the gate:
./scripts/bench-gate.sh --check /tmp/diff.txt
```

## Adjusting the threshold

The default regression threshold is 25%. To change it:

- Globally for CI: update the `THRESHOLD_PCT` env var in
  `.github/workflows/bench.yml`.
- For a single local run: `THRESHOLD_PCT=10 ./scripts/bench-gate.sh --check diff.txt`.

There is no per-benchmark threshold override at this time. If one benchmark
is routinely noisier than others, use the skip annotation (see below) or
tighten the global threshold only after addressing the noise source.

## Adding a benchmark

1. Write the benchmark in the appropriate package following the existing
   conventions (see `internal/bench/` for examples).
2. Add the benchmark name to `benchgate/curated.txt` with a comment
   explaining what regression it catches.
3. Run `BENCH_TIME=1x BENCH_COUNT=1 ./scripts/bench-gate.sh` locally to
   confirm the new benchmark appears in the output and exits 0.

## Removing a benchmark

Delete the name from `benchgate/curated.txt`. The benchmark function itself
may stay in the codebase for informational use; removing it from the curated
list excludes it from the regression gate.

## Noisy benchmark skip annotation

If a benchmark routinely produces more than 10% noise (common for
wall-clock-sensitive tests on shared CI runners), add a `# gate:skip` line
in `benchgate/curated.txt`:

```
# gate:skip BenchmarkFoo -- high variance on shared runners; tracked in issue #NNN
```

The gate script will exclude the benchmark from both the `-bench` regex and
the threshold check. The benchmark still runs if you invoke `go test -bench=.`
directly; it is only skipped by the gate tooling.

Do not skip a benchmark without a reference to a tracking issue explaining
why and when it will be un-skipped.

## CI workflow

The `bench` workflow (`.github/workflows/bench.yml`) triggers on
`workflow_dispatch` and on a cron schedule of Mondays at 06:00 UTC. It does not
trigger on pull requests or pushes. Per-PR runs were dropped because of the CI
time they cost; run it by hand before a release if you want a check.

Read from the workflow file as of 2026-10-06:

- The base commit is taken from `github.event.pull_request.base.sha` or
  `github.event.before`. Both are empty for dispatch and schedule runs, so the
  workflow sets `SKIP_DIFF` and skips the benchstat comparison and the
  threshold check. In those runs it only benchmarks the checked-out commit and
  uploads `pr-bench.txt`. The `base_sha` dispatch input is declared but no step
  reads it.
- The scheduled runs on 2026-09-21, 2026-09-28 and 2026-10-05 failed at the
  `Install benchstat` step, before any benchmark ran.
- The PR-comment step is conditioned on `pull_request` events, so it never runs
  under the current triggers.

What the workflow is built to do when it has a base commit:

- **Base caching**: the base-branch benchmark output is cached by commit SHA
  (`bench-baseline-<sha>`) so a repeat run does not re-benchmark the base.
- **Cold-base fallback**: when no cache exists the workflow checks out the base
  commit, runs the benchmarks, saves the cache, then returns to the tested SHA
  before the diff step.
- **Artifacts**: `pr-bench.txt`, `base-bench.txt`, and `diff.txt` are uploaded
  as workflow artifacts (retained 90 days).
- **benchstat**: installed via `go install golang.org/x/perf/cmd/benchstat@latest`
  in the workflow; not added to `go.mod` to avoid bloating the module graph.

To compare two commits today, use the local procedure in
[Running locally](#running-locally).

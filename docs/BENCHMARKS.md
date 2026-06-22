# theauth-go Benchmark Gate

Every pull request runs a curated benchmark suite via the `bench` GitHub
Actions workflow and fails if any benchmark regresses more than the
configured threshold (default 25%).

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

The `bench` workflow (`.github/workflows/bench.yml`) runs on every pull
request and on pushes to `main`.

Key design decisions:

- **Base caching**: the base-branch benchmark output is cached by commit SHA
  (`bench-baseline-<sha>`) so re-runs of the same PR do not re-benchmark
  the base.
- **Cold-base fallback**: when no cache exists the workflow checks out the
  base commit, runs the benchmarks, saves the cache, then returns to the PR
  SHA before the diff step.
- **PR comment**: on pull requests the diff is posted (or updated) as a PR
  comment by `github-actions[bot]` so reviewers see the delta without
  downloading artifacts.
- **Artifacts**: `pr-bench.txt`, `base-bench.txt`, and `diff.txt` are
  uploaded as workflow artifacts (retained 90 days) for post-hoc analysis.
- **benchstat**: installed via `go install golang.org/x/perf/cmd/benchstat@latest`
  in the workflow; not added to `go.mod` to avoid bloating the module graph.

# Verify it yourself

theauth-go is young. The first commit is dated 2026-06-20 and the repository had 6 stars on 2026-10-30. Stars and years of use are not something we can show you, so this page lists things you can check with a command or a link. Where a number comes from a command, the command is next to it.

Numbers were taken on 2026-10-30 from a clean checkout of `main` (commit `9166ab3`). They will drift as the repo changes, so rerun the commands rather than trusting the figures.

## What is measured, and how to reproduce it

```bash
git clone https://github.com/glincker/theauth-go && cd theauth-go

# Go modules (root, nested libraries, adapters and examples)
find . -name go.mod | wc -l                                  # 25

# Test files and non-test Go files
find . -name '*_test.go' | wc -l                             # 361
find . -name '*.go' ! -name '*_test.go' | wc -l              # 554

# Directories that hold Go files, and how many of those have tests
find . -name '*.go' | xargs -n1 dirname | sort -u | wc -l    # 154
find . -name '*_test.go' | xargs -n1 dirname | sort -u | wc -l  # 93

# Packages in the root module only
go list ./... | wc -l                                        # 129
```

Of the 25 modules, 18 are runnable examples under `examples/`. The rest are the root module, `mcpresource`, `storage/sqlite`, `audit/sinks/otlp` and the three framework adapters.

These counts show size and test presence. They say nothing about test quality or coverage. We have not published a coverage figure on this page; the Codecov badge in the README is the place to look.

## Supply chain

Every release is built by the `release` workflow (`.github/workflows/release.yml`).

- Signing: release assets are signed keyless with cosign through GitHub Actions OIDC. The exact `cosign verify-blob` steps are in the README under [Verify releases](../README.md#verify-releases).
- SBOM: each `theauth-go-v*.tar.gz` ships with a `.sbom.json`, generated with syft in the release workflow.
- Provenance: the release workflow calls `actions/attest-build-provenance` on the archive and the SBOM. The README badge claims SLSA level 3.
- Scorecard: the `scorecard` workflow runs weekly. Current results are at <https://scorecard.dev/viewer/?uri=github.com/glincker/theauth-go>.
- Code scanning: the `codeql` workflow runs weekly and on changes.
- Dependencies: the `govulncheck` workflow runs weekly, and `dependency-review` runs on pull requests.

List the workflows yourself with `ls .github/workflows`.

## Performance

We quote [docs/SCALE.md](SCALE.md) and [docs/BENCHMARKS.md](BENCHMARKS.md) and nothing else.

- Session lookup, measured at the storage layer on an Apple M4 Max with `BenchmarkSessionLookup`: one joined query took 30 us, against 58 to 67 us for the earlier two-query path.
- SCALE.md says the load test is reproducible with `scripts/loadtest.sh`.
- HTTP throughput is intentionally not published. SCALE.md explains that the server, load generator and database shared one busy laptop, so request rates varied too much to print a number. Run the script on a quiet machine and use your own result.
- BENCHMARKS.md describes a curated benchmark list with a regression gate, default threshold 25 percent. The `bench` workflow runs it weekly and on manual dispatch, not on every pull request.
- There is no head-to-head benchmark against other libraries, so we make no "faster than" claim.

## In production

theauth-go is used in the maintainers' own products. We make no claim about scale.

- Levelrail imports `github.com/glincker/theauth-go/v2` in `internal/authengine/`, and its `go.mod` pins `v2.12.0`.
- thingwire runs a service built on theauth-go in `docker/theauth/` (`main.go`, `routes.go`, `service.go`).

Both are projects of the same maintainers, so treat this as dogfooding, not independent adoption.

## Stability policy

The SemVer rules and the list of stable packages are in [STABILITY](https://docs.theauth.dev/go/reference/stability). The README [Stability](../README.md#stability) section lists what is experimental. Changes that affect behavior go in [CHANGELOG.md](../CHANGELOG.md) with upgrade notes.

## Limits and non-goals

- Age. The repo is about four months old. Expect fewer deployed configurations, fewer third-party write-ups and fewer answered questions than older libraries have.
- Maintainers. theauth-go is maintained by GLINR STUDIOS. [MAINTAINERS.md](../MAINTAINERS.md) names no individuals, so plan for a small team and check [GOVERNANCE.md](../GOVERNANCE.md) and recent commit history for yourself.
- Experimental packages. Per the README, these may change in a minor release: `storage/sqlite`, `clientauth`, `policy`, the agent identity and revocation APIs, `Doctor`, `Config.ProviderResolver` and the newer optional storage capabilities.
- Storage backends differ in which features they support. The table is in the README under Storage backends. The MySQL gate for newer features is still off in CI.
- No hosted service and no hosted login UI. It is a library you run yourself.
- Not independently reviewed. This page shows what we publish and what you can reproduce. It is not a third-party assessment.

If a claim here does not hold when you run the command, please open an issue.

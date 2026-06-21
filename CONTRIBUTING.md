# Contributing to theauth-go

Thank you for taking the time to contribute. This document covers the dev setup, test commands, commit convention, and PR process.

## Contents

- [Dev setup](#dev-setup)
- [Running tests](#running-tests)
- [Linting](#linting)
- [Commit convention](#commit-convention)
- [Pull request process](#pull-request-process)
- [Code style rules](#code-style-rules)

---

## Dev setup

**Requirements:**

- Go 1.25 or later
- Docker (for the Postgres integration tests)
- `golangci-lint` (optional, matches what CI runs)

```bash
git clone https://github.com/glincker/theauth-go.git
cd theauth-go
go mod download
```

Start a local Postgres instance for the integration tests:

```bash
docker run -d \
  --name theauth-postgres \
  -e POSTGRES_DB=theauth_test \
  -e POSTGRES_USER=theauth \
  -e POSTGRES_PASSWORD=theauth \
  -p 5432:5432 \
  postgres:16
```

Export the connection string:

```bash
export THEAUTH_TEST_DB="postgres://theauth:theauth@localhost:5432/theauth_test?sslmode=disable"
```

---

## Running tests

```bash
# all tests (unit + integration, race detector on)
go test -race ./...

# unit tests only (no DB required)
go test -short ./...

# fuzz a specific target (10 seconds)
go test -fuzz FuzzAESGCMRoundTrip -fuzztime=10s ./crypto/...

# benchmarks
go test -bench=. -benchmem ./internal/bench/...
```

The CI workflow runs `go test -race ./...` and a per-target fuzz job (`-fuzztime=10s`) on every PR.

---

## Linting

```bash
go vet ./...
golangci-lint run
```

CI enforces `godot` (doc-comment punctuation) and `godox` (stray TODO markers) via `golangci.yml`.

---

## Commit convention

```
<type>: <description>
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`

Rules:

- No em dashes, en dashes, or markdown headers in the message body
- Keep the first line under 72 characters
- Reference the issue number in the body when applicable: `Closes #123`
- No "Co-Authored-By" trailers

Examples:

```
feat: add Google OAuth provider with PKCE S256
fix: close timing side-channel on unknown-email signin branch
docs: add TOTP step-up example
```

---

## Pull request process

1. Open an issue first for anything beyond a typo or one-file fix. This saves both your time and the reviewer's time.
2. Fork the repo, create a branch from `main` named `<type>/<short-slug>`.
3. Write tests for any new behavior. No new features without tests.
4. Run `go test -race ./...` and `go vet ./...` locally before pushing.
5. Fill out the pull request template. Link to the relevant issue.
6. A maintainer will review within a few business days. Be prepared to address feedback.
7. Squash your commits if the history is noisy before merge is requested.

---

## Code style rules

- No `any` types. Define interfaces or use concrete types.
- No `@ts-nocheck` equivalent (`//nolint` without a comment explaining why is rejected).
- No `fmt.Println` or `log.Println` in production code paths. Use the library's logger or return errors.
- Max ~500 lines per file. Split into focused service files if a file grows beyond that.
- All new HTTP endpoints require auth middleware (session or bearer). No unauthenticated routes except health checks and well-known discovery endpoints.
- New storage operations go behind an optional interface (type-asserted at runtime) to avoid breaking the base `Storage` interface. See [STABILITY.md](STABILITY.md) for the special rule.
- New entities need a corresponding test tagged `unit` or backed by the in-memory adapter so the suite runs without Postgres.

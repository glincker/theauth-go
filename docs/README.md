# Docs

The Go library documentation lives at <https://docs.theauth.dev/go>.

Its source is in the [glincker/theauth](https://github.com/glincker/theauth) repository under `docs/go/`. To fix or add a page, open a pull request there, not here. The MkDocs site that used to be built from `docs-site/` has been retired.

Files kept in this directory are internal or repo-level references that code, tests or release tooling use: `AGENTS.md`, `BENCHMARKS.md`, `RELEASING.md`, `REPO-LAYOUT.md`, `ROADMAP.md`, `SECURITY.md`, `SECURITY-DOCTOR.md` (read by `integration/doctor_test.go`), `positioning.md` and `release-notes-v2.6.0.md`.

Feature guides for the OAuth server and shared state are kept here until they move to the docs site: [pluggable-stores.md](pluggable-stores.md), [oauth-endpoint-limits.md](oauth-endpoint-limits.md), [device-authorization.md](device-authorization.md) [registration-tokens.md](registration-tokens.md), [device-tokens.md](device-tokens.md), [oidc-provider.md](oidc-provider.md), [admission.md](admission.md), [otp.md](otp.md), [provider-catalog.md](provider-catalog.md) and [cli.md](cli.md).

## Development hooks

Tracked git hooks live in `.githooks/`. Install them once per clone with `sh scripts/install-hooks.sh`.

| Hook | What it checks |
| --- | --- |
| `pre-commit` | gofmt on staged Go files, and no em or en dashes in added lines |
| `commit-msg` | no dashes in the subject, no AI attribution trailers |
| `pre-push` | `golangci-lint --new-from-rev=origin/main`, a `GOWORK=off` build and vet of every touched module, and `govulncheck` per touched module |

The `pre-push` hook mirrors CI so lint, nested module builds and dependency vulnerabilities fail on your machine first. Third-party module findings fail the push. Standard library findings only warn, because they follow your local Go version, so keep the toolchain current. Bypass in an emergency with `THEAUTH_SKIP_HOOKS=1 git push`.

# Docs

The Go library documentation lives at <https://docs.theauth.dev/go>.

Its source is in the [glincker/theauth](https://github.com/glincker/theauth) repository under `docs/go/`. To fix or add a page, open a pull request there, not here. The MkDocs site that used to be built from `docs-site/` has been retired.

Files kept in this directory are internal or repo-level references that code, tests or release tooling use: `AGENTS.md`, `BENCHMARKS.md`, `RELEASING.md`, `REPO-LAYOUT.md`, `ROADMAP.md`, `SECURITY.md`, `SECURITY-DOCTOR.md` (read by `integration/doctor_test.go`), `positioning.md` and `release-notes-v2.6.0.md`.

Feature guides for the OAuth server, agents and shared state are kept here until they move to the docs site.

Running it:

- [dev-mode.md](dev-mode.md): `go run .../cmd/theauth-dev@latest` starts a seeded in-memory server and walks through an agent, a delegation, an allowed and a denied tool call, and a verified audit chain.
- [mcp-oauth-sqlite.md](mcp-oauth-sqlite.md): the OAuth 2.1 authorization server on SQLite for an MCP server, including mounting under a path prefix and revocation with `mcpresource`.
- [approvals.md](approvals.md): HTTP inbox to list, approve and deny agent tool approvals with four-eyes and audit.
- [storage-capabilities.md](storage-capabilities.md): which capability interfaces each backend (memory, SQLite, Postgres, MySQL) implements, with migration numbers.
- [pluggable-stores.md](pluggable-stores.md): shared rate limits, replay cache and document cache across replicas.

Authorization server:

- [oauth-consent.md](oauth-consent.md), [session-auth-methods.md](session-auth-methods.md), [access-token-policy.md](access-token-policy.md), [rich-authorization-requests.md](rich-authorization-requests.md), [oauth-endpoint-limits.md](oauth-endpoint-limits.md), [mcp-metadata-paths.md](mcp-metadata-paths.md), [client-compat.md](client-compat.md), [oidc-provider.md](oidc-provider.md), [id-jag.md](id-jag.md), [device-authorization.md](device-authorization.md), [registration-tokens.md](registration-tokens.md), [device-tokens.md](device-tokens.md), [token-vault.md](token-vault.md) and [admission.md](admission.md).

Agents and audit:

- [ai-assistants.md](ai-assistants.md).
- [agent-expiry.md](agent-expiry.md), [agent-policies.md](agent-policies.md) and [policy-shrink.md](policy-shrink.md).
- [shared-signals.md](shared-signals.md).

Other guides: [otp.md](otp.md), [enumeration-safe-passwordless.md](enumeration-safe-passwordless.md), [passkey-attestation.md](passkey-attestation.md), [hooks.md](hooks.md), [create-user.md](create-user.md), [provider-catalog.md](provider-catalog.md), [cli.md](cli.md) and [MIGRATING-FROM-KEYCLOAK.md](MIGRATING-FROM-KEYCLOAK.md).

## Development hooks

Tracked git hooks live in `.githooks/`. Install them once per clone with `sh scripts/install-hooks.sh`.

| Hook | What it checks |
| --- | --- |
| `pre-commit` | gofmt on staged Go files, and no em or en dashes in added lines |
| `commit-msg` | no dashes in the subject, no AI attribution trailers |
| `pre-push` | `golangci-lint --new-from-rev=origin/main`, a `GOWORK=off` build and vet of every touched module, and `govulncheck` per touched module |

The `pre-push` hook mirrors CI so lint, nested module builds and dependency vulnerabilities fail on your machine first. Third-party module findings fail the push. Standard library findings only warn, because they follow your local Go version, so keep the toolchain current. Bypass in an emergency with `THEAUTH_SKIP_HOOKS=1 git push`.

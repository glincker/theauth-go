# Install and packages

Moved from the README. Install steps, release verification and the package index.

```bash
go get github.com/glincker/theauth-go/v2
go get github.com/glincker/theauth-go/storage/sqlite   # optional, embedded SQLite backend
```

The module path ends in `/v2`. The first resolvable v2 tag is `v2.6.0`, and the old path without `/v2` is frozen at `v1.0.0`. See [Migrating to /v2](https://docs.theauth.dev/go/migrations/to-v2-module-path).

## Verify releases

Release assets are signed keyless with cosign through GitHub Actions OIDC. Download `checksums.txt`, `checksums.txt.sig` and `checksums.txt.cert` from the release, then verify (replace `v2.8.0` with your tag):

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/glincker/theauth-go/.github/workflows/release.yml@refs/tags/v2.8.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig --certificate checksums.txt.cert checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

Each `theauth-go-v*.tar.gz` and its `.sbom.json` also ship with `.sig` and `.cert` files that verify the same way.

## Packages

One Go module at the root plus three nested modules (`mcpresource`, `storage/sqlite`, `audit/sinks/otlp`) that carry their own dependencies. Everything else is a package inside the root module. Full index on [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2).

| Group | Packages |
|---|---|
| Core | `theauth-go/v2` (server, sessions, OAuth 2.1 authorization server, agent identity, MCP authorization), `admin`, `crypto`, `email`, [`policy`](https://docs.theauth.dev/go/guides/policy-engine), [`clientauth`](https://docs.theauth.dev/go/guides/cli-login) (device login for Go CLIs), [`otp`](./otp.md), `openapi`, [`mcpresource`](https://docs.theauth.dev/go/concepts/resource-server) (separate module) |
| Storage | `storage`, `storage/memory`, `storage/postgres`, `storage/mysql`, `storage/sqlite` (separate module), [`storagetest`](https://docs.theauth.dev/go/guides/custom-storage-backend) |
| Audit sinks | `audit/sinks/splunkhec`, `audit/sinks/webhook`, `audit/sinks/otlp` (separate module) |
| Gin adapter | [`adapters/gin`](../adapters/gin) (separate module): native `Authn`, `RequireAuth`, `RequireAbility`, accessors and `Mount` |
| Echo adapter | [`adapters/echo`](../adapters/echo) (separate module): the same set for Echo v4 |
| Fiber adapter | [`adapters/fiber`](../adapters/fiber) (separate module): the same set for Fiber v2 through its net/http adaptor (responses are buffered) |
| Providers | `provider/` apple, bitbucket, discord, facebook, github, gitlab, google, linkedin, microsoft, slack, twitch, x, oidc, and [`generic`](./provider-catalog.md) for 16 more (Spotify, Dropbox, Zoom, Kakao, Naver, Patreon, Box, Salesforce, Figma, Codeberg, Linear, PayPal, Kick, Hugging Face, Vercel, Yandex) |
| Commands | [`theauth-go`](./cli.md) (secrets, OpenAPI), [`theauth-doctor`](https://docs.theauth.dev/go/guides/security-doctor) (security doctor), [`theauth-migrate`](https://docs.theauth.dev/go/migrations/migration-guide) (Auth0 and Cognito import) |

## Modules on pkg.go.dev

| Module | Go | Reference |
|---|---|---|
| `github.com/glincker/theauth-go/v2` | 1.25 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2) |
| `github.com/glincker/theauth-go/mcpresource` | 1.25 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/mcpresource) |
| `github.com/glincker/theauth-go/storage/sqlite` | 1.26 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/storage/sqlite) |
| `github.com/glincker/theauth-go/adapters/gin` | 1.26 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/adapters/gin) |
| `github.com/glincker/theauth-go/adapters/echo` | 1.26 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/adapters/echo) |
| `github.com/glincker/theauth-go/adapters/fiber` | 1.26 | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/adapters/fiber) |

The TypeScript packages are listed in the [theAuth README](https://github.com/glincker/theauth#packages).

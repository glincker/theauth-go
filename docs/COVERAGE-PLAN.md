# Coverage plan

Measured 2026-10-31 on the root module (`go test ./...`, mcpresource and storage/sqlite are separate modules and are not included).

## Two numbers

| Measure | Command | Before | After this branch |
| --- | --- | --- | --- |
| Per-package own tests only | `go test -coverprofile=c.out ./...` | 44.7% | 45.2% |
| Cross-package (integration suite counted) | `go test -coverpkg=./... -coverprofile=c.out ./...` | 67.6% | 67.7% |

The first number is what a plain `go test ./...` upload reports. Much of the security surface (OAuth callbacks, password and TOTP handlers, SCIM, API tokens) is exercised by the black-box suite in `integration/`, which a per-package profile does not credit to the package under test. The second number credits it. Both include `storage/postgres`, `storage/mysql` and `cmd/*` (needing a real database or binary), which pull the total down.

Target: 80% on the cross-package measure, and 80% own-test coverage for every package in the table below.

## Security-relevant packages, lowest first

| Package | Own tests | Cross-package | Notes |
| --- | --- | --- | --- |
| internal/apitokens | 0.5% | 76.9% | covered by integration only |
| internal/password/handlers | 2.5% | 82.3% | integration only |
| internal/totp/handlers | 3.0% | 70.3% | integration only |
| internal/oauth/handlers | 7.7% | 86.2% | integration only |
| internal/password | 18.6% | 86.5% | |
| internal/as/handlers | 24.4% | 79.6% | |
| internal/agent | 29.0% | 81.7% | |
| internal/identitylink | 30.1% | 78.6% | |
| internal/oauth | 31.6% | 86.1% | provider login service |
| internal/models | 33.3% | 63.4% | error and helper types |

Also at 0% own-test: internal/account, internal/agent/handlers, internal/scim/handlers, internal/magiclink, internal/totp.

## Added in this branch

| Package | Own tests before | After | What |
| --- | --- | --- | --- |
| internal/httpsec | 51.2% | 98.4% | CSRF origin check matrix, Secure cookie rewriting |
| internal/revocation | 15.1% | 83.9% | event matching per credential kind, bus, watch cancel, bearer poll |
| internal/jwt | 64.9% | 82.8% | signature-only verify (typ confusion, tamper, unknown kid), header peek, claim merge |
| internal/dpop | 74.1% | 78.6% | RFC 9449 ath vector, Ed25519 key validation, config accessors |

Fuzz targets (seed corpus includes empty, huge, unicode and NUL inputs): `FuzzBearerToken` (internal/apitokens), `FuzzParseProofAndVerify` (internal/dpop), `FuzzValidateRedirectURI` (internal/cimd). PKCE fuzzing already existed in `crypto`.

## Next steps

1. Unit tests next to internal/apitokens, internal/oauth/handlers, internal/password/handlers and internal/totp/handlers, so they stop relying on the integration suite.
2. Report the cross-package profile (`-coverpkg=./...`) to Codecov alongside the per-package one.
3. Run storage/postgres and storage/mysql tests against a service container in CI.
4. Exclude `examples/` and generated `sqlc` code from the profile.

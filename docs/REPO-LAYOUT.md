# Repository layout

The module root holds only the public face of the library. Feature code
lives in `internal/<feature>` packages and the root re-exports what
consumers use. v2.6.0 was never tagged, so this restructure ships before the
first `/v2` release.

## Rules

- Root files are the public face: `doc.go`, `theauth.go`, `wiring.go`,
  `config*.go`, `errors.go`, `models.go`, `storage*.go`, `handlers.go`,
  `middleware.go`, plus one thin facade per feature. A facade only holds
  `(*TheAuth)` methods, aliases and adapters, because Go methods must live in
  the receiver's package.
- Names that adapters or callers use stay at the root as type aliases or
  re-exported values, so `errors.Is` and type assertions keep working.
- Black-box tests live in `integration/`. White-box tests live with the code
  they test. Test-only access to unexported root behavior goes through
  `internal/testhooks`, registered by `testhooks.go`, so no public API is added.
- Internal packages never import the root. The root passes narrow interfaces
  (for example `apitokens.Host`) in.

## Move map

| Old root files | New home |
| --- | --- |
| 30 black-box `*_test.go` files, `testdata/` | `integration/` (package `integration`) |
| `export_test.go`, `apitoken_export_test.go` | `integration/internal/testutil` over `internal/testhooks` |
| `models_test.go` | `internal/models` |
| `apitoken_*.go`, `device*.go`, `agent_identity.go`, `principal_resolve.go` | `internal/apitokens` (service, device grant, routes, middleware, principal); `RegisterAgent` in `internal/agent`; root facade `apitokens.go` |
| `revocation.go` | `internal/revocation` (bus, target, watcher); root facade `revocation.go` |
| `doctor.go`, `doctor_checks.go`, `doctor_handler.go`, `doctor_internal_test.go` | `internal/doctor` (pure checks over `Input`); root facade `doctor.go` gathers the input |
| `import.go` | `internal/importer`; root facade `import.go` |
| `bootstrap.go`, `hardening.go` | `internal/bootstrap`; config pieces in `config_security.go`; methods in `forwarders.go` |
| `middleware_ratelimit.go`, `http_security.go` | `internal/ratelimit`, `internal/httpsec`; wrappers merged into `middleware.go` |
| `authevents.go`, `observability.go` redaction | `internal/authevents`, `internal/audit/redact.go` |
| RBAC catalog in `enterprise.go` | `internal/rbac/catalog.go` |
| `errors_hardening.go`, `storage_hardening.go` | merged into `errors.go`, `storage_caps.go` |
| `domains.go` | merged into `models.go` |
| `as.go` | `config_as.go` |
| `handlers_sessions.go`, `service_sessions.go` | `sessions.go` |
| `handlers_admin.go`, `handlers_domains.go` | `mounts.go` |
| `storage_sessions.go`, `storage_unsupported.go` | `storage_caps_sessions.go`, `storage_caps_unsupported.go` |
| `sqlc.yaml` | `storage/postgres/sqlc.yaml` |

## Not moved

- `sessions.go` (session management, step-up, session links) still holds real
  logic on `*TheAuth` because it reads many root fields. Extracting it needs a
  host interface like `apitokens.Host`; left for a follow-up.
- `mounts.go` holds the adapters that bind internal handler packages to
  `*TheAuth`. They are wiring, not feature code.
- `forwarders.go`, `services.go`, `enterprise.go` are the thin method facades
  for flows whose logic already lives in `internal/*` packages.

## Verification

The exported root API was diffed before and after with `go/types` (names,
struct fields, method sets): no difference other than the printed name of the
alias target. The Test function count is unchanged (868).

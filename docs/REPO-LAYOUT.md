# Repository layout

The module root holds only the public face of the library. Feature code
lives in `internal/<feature>` packages and the root re-exports what
consumers use. Nothing here is released yet: v2.6.0 was never tagged, so
the directory restructure ships before the first `/v2` release.

## Rules

- Root files: `doc.go`, `theauth.go`, `wiring.go`, `config*.go`, `errors.go`,
  `models.go`, `storage*.go`, `handlers.go`, plus thin one-file-per-feature
  facades. A facade only holds `(*TheAuth)` methods and aliases, because
  Go methods must live in the receiver's package.
- Models, config pieces, results and errors that adapters or callers name
  stay available at the root as type aliases or re-exported values, so
  `errors.Is` and type assertions keep working across the boundary.
- Black-box tests live in `integration/`. White-box tests move with the code
  they test. No test is deleted or weakened.
- Test-only access to unexported root internals goes through
  `internal/testhooks`, registered by one root file. It adds no public API.

## Move map

| Old root files | New home |
| --- | --- |
| 34 `*_test.go` black-box files | `integration/` (package `integration`) |
| `export_test.go`, `apitoken_export_test.go` | `integration/internal/testutil` over `internal/testhooks` |
| `models_test.go` | `internal/models` |
| `doctor.go`, `doctor_checks.go`, `doctor_internal_test.go` | `internal/doctor` (pure checks over `Input`); root keeps `Doctor`, `Report`, `Finding`, `Severity` aliases and the `Doctor*` ids |
| `import.go` | `internal/importer`; root keeps wrappers and aliases |
| `apitoken_*.go`, `device*.go`, `agent_identity.go`, `principal_resolve.go` | `internal/apitokens` (service, device grant, handlers) behind a small `Host` interface; root keeps `(*TheAuth)` facades and aliases |
| `revocation.go` | `internal/revocation` (bus, targets, watcher); root keeps facade |
| `hardening.go`, `errors_hardening.go`, `http_security.go`, `middleware*.go`, `bootstrap.go` | matching `internal` packages where free of `*TheAuth`, otherwise merged into `handlers.go` or `wiring.go` |
| `handlers_sessions.go`, `service_sessions.go`, `handlers_admin*.go`, `handlers_domains.go`, `domains.go`, `enterprise.go` | per-feature internal packages with root facades |
| `authevents.go`, `observability.go`, `forwarders.go`, `services.go` | pure helpers (redaction, event types, hooks) to internal packages, facades stay as one file per feature |
| `sqlc.yaml` | `storage/postgres/sqlc.yaml` |

## Risks

- Import cycles: internal packages never import the root. The root passes
  narrow interfaces (`Host`) in.
- Aliases keep exported names. Anything that cannot be aliased (unexported
  fields, test-only exports) is listed under "Breaking (directory layout)"
  in the changelog and in the module path migration page.
- Per-phase gate: gofmt, build, vet, `go test -short`, lint (new and full
  counts), and the sqlite race run. Test function count must not drop
  (baseline 868, root package 213).

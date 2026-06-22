// Package observability is the pluggable tracing + metrics adapter surface
// the theauth-go library uses to expose spans and counters without pulling
// in OpenTelemetry, Prometheus, or any other vendor as a hard dependency.
//
// Design:
//
//   - Consumers wire their own Tracer and Metrics implementations via
//     theauth.Config.Observability. The library never imports otel or prom
//     so go.mod stays clean for downstream consumers who pick a different
//     stack (Datadog, NewRelic, vendored exporters, or no observability at
//     all).
//
//   - Every interface is nil-safe at the call site through the helper
//     methods on *Hooks (StartSpan, IncCounter, etc.). Internal service
//     packages take a *Hooks pointer and call those helpers so they never
//     branch on nil at every emit site.
//
//   - Cardinality discipline lives at the call site: client_id, user_id,
//     and other high-cardinality identifiers go on spans (as attributes),
//     never on metric labels. The exposed metric label sets are bounded
//     and documented in the package matrix in docs/OBSERVABILITY.md.
//
//   - Reference adapters live under examples/observability-otel and
//     examples/observability-prom. Each is a separate Go module with its
//     own go.mod, so the reference adapters' imports never leak into the
//     root go.sum.
//
// The package is internal so the exposed surface stays exactly the
// re-exports declared in the root theauth package (theauth.Tracer,
// theauth.Metrics, theauth.Hooks, etc.). Adding a new metric or span
// label means editing this package and the matching root re-export in
// one commit, which keeps the public API auditable in a single diff.
package observability

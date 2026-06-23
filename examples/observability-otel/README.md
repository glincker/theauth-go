# observability-otel

Reference adapter bridging `theauth.Tracer` to `go.opentelemetry.io/otel`.

This module is intentionally small (under 100 lines of production code) so consumers can copy it inline into their own service if they need a tweaked version (custom span kind, resource attributes per span, etc.).

## Use

```go
import (
    "github.com/glincker/theauth-go"
    otelbridge "github.com/glincker/theauth-go/examples/observability-otel"
    "go.opentelemetry.io/otel"
)

tracer := otel.Tracer("my-service")
hooks := &theauth.Hooks{Tracer: otelbridge.New(tracer)}

auth, _ := theauth.New(theauth.Config{
    Storage:       store,
    BaseURL:       "https://example.com",
    Observability: hooks,
})
```

The bridge is dep-isolated: it lives in its own `go.mod` so importing `theauth-go` itself does not pull in the OpenTelemetry SDK.

## Cardinality discipline

The library already keeps high-cardinality identifiers (client_id, user_id, session_id, IP) on spans as attributes, never on metric labels. The bridge surfaces those attributes verbatim through `Span.SetAttributes`; you do not need a custom processor to strip them.

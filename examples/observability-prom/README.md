# observability-prom

Reference adapter bridging `theauth.Metrics` to `github.com/prometheus/client_golang/prometheus`.

## Use

```go
import (
    "net/http"

    "github.com/glincker/theauth-go"
    prombridge "github.com/glincker/theauth-go/examples/observability-prom"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

reg := prometheus.NewRegistry()
metrics := prombridge.New(reg)
hooks := &theauth.Hooks{Metrics: metrics}

auth, _ := theauth.New(theauth.Config{
    Storage:       store,
    BaseURL:       "https://example.com",
    Observability: hooks,
})

http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
```

## Cardinality discipline

The library only emits low-cardinality metric labels (`grant_type`, `status`, `rule`, `kind`). High-cardinality identifiers (`client_id`, `user_id`, etc.) live on spans, never on metric labels. The bridge memoizes by `(name, label-name-set)` so accidental label-set drift on the same metric name is caught at registration time.

## Histogram buckets

The library passes `theauth.LatencyBuckets` for every `_latency_seconds` metric. The bridge uses whatever buckets the library supplies on the FIRST `Histogram(name, ...)` call; subsequent calls re-use the same vec regardless of supplied buckets (a Prometheus constraint, not a bridge choice).

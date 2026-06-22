package observability

// Metrics is the minimal counter / histogram / gauge factory adapters
// implement. Consumers wire a concrete Metrics (typically backed by
// github.com/prometheus/client_golang/prometheus) via
// theauth.Config.Observability.Metrics; the library calls the factory
// methods at service-construction time and stores the returned instruments
// on the service.
//
// Adapters MUST cache instruments by (name, label set) so repeated calls
// with the same arguments return the same instrument. The library does NOT
// memoize on its side: every call to Hooks.Counter / Hooks.Histogram /
// Hooks.Gauge is a fresh call into the adapter, and the adapter is
// expected to return a stable instrument. This matches how the otel and
// prometheus client libraries already cache internally.
//
// Implementations MUST be safe to call from any goroutine.
type Metrics interface {
	// Counter returns a monotonic counter. labels enumerates the LABEL
	// VALUES (not names) for the instance; the names are part of the
	// metric definition and are documented in the matrix in
	// docs/OBSERVABILITY.md. Adapters that need label names register
	// them on first Counter call.
	Counter(name string, labels Labels) Counter

	// Histogram returns a distribution histogram with the supplied bucket
	// boundaries (in the unit of the observed value, e.g. seconds for
	// _latency_seconds metrics). buckets MUST be sorted ascending; the
	// adapter MAY assume so.
	Histogram(name string, labels Labels, buckets []float64) Histogram

	// Gauge returns a settable gauge.
	Gauge(name string, labels Labels) Gauge
}

// Counter is a monotonic counter. The library only calls Inc() and Add().
// Implementations MUST be safe to call from any goroutine.
type Counter interface {
	Inc()
	Add(delta float64)
}

// Histogram is a distribution histogram. The library only calls Observe().
// Implementations MUST be safe to call from any goroutine.
type Histogram interface {
	Observe(value float64)
}

// Gauge is a settable, incrementable, decrementable instantaneous value.
// Implementations MUST be safe to call from any goroutine.
type Gauge interface {
	Set(value float64)
	Inc()
	Dec()
}

// Labels is the (name -> value) label set for a single metric instance.
// Adapters that pre-register labels treat the keys as the label name set
// the first time a given metric name is seen. Subsequent calls for the
// same name with a different key set is a programmer error; adapters MAY
// log a warning and ignore the unknown keys.
//
// Cardinality discipline: callers MUST NOT put high-cardinality identifiers
// (client_id, user_id, session_id, IP) into Labels. Those go on spans as
// attributes. The label set for each library-emitted metric is documented
// in docs/OBSERVABILITY.md and enforced by review.
type Labels map[string]string

// NoopMetrics is the default Metrics used when Hooks.Metrics is nil. Every
// instrument it returns is a no-op so the library never branches on a nil
// metrics adapter at the emit site.
type NoopMetrics struct{}

// Counter on NoopMetrics returns a NoopCounter.
func (NoopMetrics) Counter(_ string, _ Labels) Counter { return noopCounter{} }

// Histogram on NoopMetrics returns a NoopHistogram.
func (NoopMetrics) Histogram(_ string, _ Labels, _ []float64) Histogram { return noopHistogram{} }

// Gauge on NoopMetrics returns a NoopGauge.
func (NoopMetrics) Gauge(_ string, _ Labels) Gauge { return noopGauge{} }

type noopCounter struct{}

func (noopCounter) Inc()          {}
func (noopCounter) Add(_ float64) {}

type noopHistogram struct{}

func (noopHistogram) Observe(_ float64) {}

type noopGauge struct{}

func (noopGauge) Set(_ float64) {}
func (noopGauge) Inc()          {}
func (noopGauge) Dec()          {}

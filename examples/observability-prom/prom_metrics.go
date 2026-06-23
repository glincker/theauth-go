// Package prombridge bridges theauth.Metrics to
// github.com/prometheus/client_golang/prometheus.
//
// Usage:
//
//	import (
//	    "github.com/glincker/theauth-go"
//	    prombridge "github.com/glincker/theauth-go/examples/observability-prom"
//	    "github.com/prometheus/client_golang/prometheus"
//	)
//
//	reg := prometheus.NewRegistry()
//	metrics := prombridge.New(reg)
//	hooks := &theauth.Hooks{Metrics: metrics}
//	auth, _ := theauth.New(theauth.Config{
//	    ...
//	    Observability: hooks,
//	})
//
// The bridge memoizes instruments by (name, label-name-set) so repeated
// calls from the library return the same underlying *prometheus.MetricVec
// child. Label cardinality discipline lives at the library call site
// (high-cardinality identifiers go on spans, not metric labels); the
// bridge does not police that.
package prombridge

import (
	"sort"
	"strings"
	"sync"

	"github.com/glincker/theauth-go"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the bridge satisfying theauth.Metrics.
type Metrics struct {
	reg prometheus.Registerer

	mu         sync.Mutex
	counters   map[string]*prometheus.CounterVec
	histograms map[string]*prometheus.HistogramVec
	gauges     map[string]*prometheus.GaugeVec
}

// New returns a bridge that registers instruments on the supplied
// Registerer. Pass prometheus.DefaultRegisterer for the default global
// registry, or a fresh prometheus.NewRegistry() for a scoped subset.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	return &Metrics{
		reg:        reg,
		counters:   map[string]*prometheus.CounterVec{},
		histograms: map[string]*prometheus.HistogramVec{},
		gauges:     map[string]*prometheus.GaugeVec{},
	}
}

// Counter returns a Prometheus counter child for the supplied labels. The
// underlying *CounterVec is created once per metric name; subsequent calls
// with the same name MUST use the same label name set (the library does;
// callers using these helpers from their own code should follow the same
// discipline).
func (m *Metrics) Counter(name string, labels theauth.Labels) theauth.Counter {
	names := labelNames(labels)
	vec := m.counterVec(name, names)
	return promCounter{c: vec.With(labelValues(names, labels))}
}

// Histogram returns a Prometheus histogram child. buckets MUST match
// between calls for the same metric name; the first call wins.
func (m *Metrics) Histogram(name string, labels theauth.Labels, buckets []float64) theauth.Histogram {
	names := labelNames(labels)
	vec := m.histogramVec(name, names, buckets)
	return promHistogram{h: vec.With(labelValues(names, labels))}
}

// Gauge returns a Prometheus gauge child.
func (m *Metrics) Gauge(name string, labels theauth.Labels) theauth.Gauge {
	names := labelNames(labels)
	vec := m.gaugeVec(name, names)
	return promGauge{g: vec.With(labelValues(names, labels))}
}

func (m *Metrics) counterVec(name string, labelNames []string) *prometheus.CounterVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := vecKey(name, labelNames)
	if v, ok := m.counters[key]; ok {
		return v
	}
	v := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: helpFor(name),
	}, labelNames)
	if err := m.reg.Register(v); err != nil {
		// Race: another goroutine registered first. Reuse via AlreadyRegisteredError.
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			v = are.ExistingCollector.(*prometheus.CounterVec)
		}
	}
	m.counters[key] = v
	return v
}

func (m *Metrics) histogramVec(name string, labelNames []string, buckets []float64) *prometheus.HistogramVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := vecKey(name, labelNames)
	if v, ok := m.histograms[key]; ok {
		return v
	}
	v := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    helpFor(name),
		Buckets: buckets,
	}, labelNames)
	if err := m.reg.Register(v); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			v = are.ExistingCollector.(*prometheus.HistogramVec)
		}
	}
	m.histograms[key] = v
	return v
}

func (m *Metrics) gaugeVec(name string, labelNames []string) *prometheus.GaugeVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := vecKey(name, labelNames)
	if v, ok := m.gauges[key]; ok {
		return v
	}
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: helpFor(name),
	}, labelNames)
	if err := m.reg.Register(v); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			v = are.ExistingCollector.(*prometheus.GaugeVec)
		}
	}
	m.gauges[key] = v
	return v
}

func labelNames(labels theauth.Labels) []string {
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func labelValues(names []string, labels theauth.Labels) prometheus.Labels {
	out := make(prometheus.Labels, len(names))
	for _, n := range names {
		out[n] = labels[n]
	}
	return out
}

func vecKey(name string, labelNames []string) string {
	return name + "|" + strings.Join(labelNames, ",")
}

// helpFor returns a best-effort help string. Operators can post-process
// the registered instruments to override; this exists so the metrics
// endpoint never serves a HELP-less metric (which the Prometheus linter
// flags).
func helpFor(name string) string {
	return "theauth-go: " + name
}

type promCounter struct {
	c prometheus.Counter
}

func (p promCounter) Inc()          { p.c.Inc() }
func (p promCounter) Add(d float64) { p.c.Add(d) }

type promHistogram struct {
	h prometheus.Observer
}

func (p promHistogram) Observe(v float64) { p.h.Observe(v) }

type promGauge struct {
	g prometheus.Gauge
}

func (p promGauge) Set(v float64) { p.g.Set(v) }
func (p promGauge) Inc()          { p.g.Inc() }
func (p promGauge) Dec()          { p.g.Dec() }

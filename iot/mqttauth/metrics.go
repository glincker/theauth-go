package mqttauth

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// counters are Prometheus style monotonic counters keyed by name and one label value. The key set
// is tiny and fixed after warm up, so the hot path is a shared lock read plus an atomic add.
type counters struct {
	mu sync.RWMutex
	m  map[[2]string]*atomic.Int64
}

func (c *counters) inc(name, label string) {
	k := [2]string{name, label}
	c.mu.RLock()
	v := c.m[k]
	c.mu.RUnlock()
	if v == nil {
		c.mu.Lock()
		if c.m == nil {
			c.m = map[[2]string]*atomic.Int64{}
		}
		if v = c.m[k]; v == nil {
			v = new(atomic.Int64)
			c.m[k] = v
		}
		c.mu.Unlock()
	}
	v.Add(1)
}

// Snapshot returns the counters as "name{result=\"label\"}" keys.
func (c *counters) snapshot() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int64, len(c.m))
	for k, v := range c.m {
		out[fmt.Sprintf("%s{result=%q}", k[0], k[1])] = v.Load()
	}
	return out
}

// MetricsHandler serves the counters in the Prometheus text exposition format:
// theauth_mqtt_authn_total, theauth_mqtt_authz_total, theauth_mqtt_cache_hits_total and
// theauth_mqtt_errors_total. It needs no client library.
func (h *Handler) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := h.metrics.snapshot()
		keys := make([]string, 0, len(snap))
		for k := range snap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		for _, k := range keys {
			_, _ = fmt.Fprintf(w, "%s %d\n", k, snap[k])
		}
	})
}

// Metrics returns a snapshot of the counters for tests and custom exporters.
func (h *Handler) Metrics() map[string]int64 { return h.metrics.snapshot() }

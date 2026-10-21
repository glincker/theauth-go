package fleet

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"time"
)

// LatencySummary is the distribution of one operation. Percentiles use the nearest rank method.
type LatencySummary struct {
	Count int
	P50   time.Duration
	P99   time.Duration
	Max   time.Duration
}

// Recorder collects wall clock durations by operation name. It is safe for concurrent use.
type Recorder struct {
	mu      sync.Mutex
	samples map[string][]time.Duration
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{samples: map[string][]time.Duration{}} }

// Time runs f and records how long it took under name.
func (r *Recorder) Time(name string, f func()) {
	start := time.Now()
	f()
	r.Record(name, time.Since(start))
}

// Record adds one sample.
func (r *Recorder) Record(name string, d time.Duration) {
	r.mu.Lock()
	r.samples[name] = append(r.samples[name], d)
	r.mu.Unlock()
}

// Report summarizes every operation.
func (r *Recorder) Report() map[string]LatencySummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]LatencySummary, len(r.samples))
	for name, s := range r.samples {
		out[name] = Summarize(s)
	}
	return out
}

// Percentile is the nearest rank percentile (0 to 100) of the samples, 0 for none.
func Percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(p/100*float64(len(sorted)) + 0.999999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// Summarize computes count, p50, p99 and max.
func Summarize(samples []time.Duration) LatencySummary {
	if len(samples) == 0 {
		return LatencySummary{}
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return LatencySummary{Count: len(sorted), P50: Percentile(sorted, 50), P99: Percentile(sorted, 99), Max: sorted[len(sorted)-1]}
}

// MemorySample is Go runtime memory in bytes: HeapInuse is live heap spans, Sys is what the runtime
// asked the OS for (an upper bound on resident memory that includes stacks and the SQL or key material).
type MemorySample struct {
	HeapInuse uint64
	Sys       uint64
}

// SampleMemory reads the runtime counters without forcing a garbage collection.
func SampleMemory() MemorySample {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemorySample{HeapInuse: m.HeapInuse, Sys: m.Sys}
}

// forEach runs task for every item with at most concurrency tasks in flight.
func forEach[T any](ctx context.Context, items []T, concurrency int, task func(T)) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(it T) {
			defer func() { <-sem; wg.Done() }()
			task(it)
		}(it)
	}
	wg.Wait()
}

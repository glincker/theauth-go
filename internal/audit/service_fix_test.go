package audit

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

type slowStore struct {
	delay   time.Duration
	release chan struct{}
	written atomic.Int64
}

func (s *slowStore) InsertAuditEvents(_ context.Context, ev []models.AuditEvent) error {
	if s.release != nil {
		<-s.release
	} else {
		time.Sleep(s.delay)
	}
	s.written.Add(int64(len(ev)))
	return nil
}

func (s *slowStore) QueryAuditEvents(context.Context, models.AuditQuery) ([]models.AuditEvent, string, error) {
	return nil, "", nil
}

func TestStopWaitsForInflightFlush(t *testing.T) {
	tests := []struct {
		name         string
		drainTimeout time.Duration
		storeDelay   time.Duration
		flushTimeout time.Duration
		wantWritten  int64
		wantDropped  uint64
	}{
		{"flush outlasts drain timeout but completes", 20 * time.Millisecond, 200 * time.Millisecond, 5 * time.Second, 1, 0},
		{"fast flush", time.Second, 0, 5 * time.Second, 1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := flushTimeout
			flushTimeout = tc.flushTimeout
			defer func() { flushTimeout = old }()
			st := &slowStore{delay: tc.storeDelay}
			svc := NewService(st, Config{DrainTimeout: tc.drainTimeout, FlushInterval: time.Hour})
			_ = svc.Start()
			svc.EmitAudit(context.Background(), "x.y", models.TargetRef{}, nil)
			time.Sleep(10 * time.Millisecond)
			svc.Stop()
			if got := st.written.Load(); got != tc.wantWritten {
				t.Fatalf("written=%d want %d", got, tc.wantWritten)
			}
			if got := svc.Counters().Dropped; got != tc.wantDropped {
				t.Fatalf("dropped=%d want %d", got, tc.wantDropped)
			}
		})
	}
}

func TestStopBoundedAndCountsLost(t *testing.T) {
	old := flushTimeout
	flushTimeout = 50 * time.Millisecond
	defer func() { flushTimeout = old }()
	st := &slowStore{release: make(chan struct{})}
	defer close(st.release)
	svc := NewService(st, Config{DrainTimeout: 10 * time.Millisecond, FlushInterval: time.Hour, BatchSize: 1})
	_ = svc.Start()
	for i := 0; i < 3; i++ {
		svc.EmitAudit(context.Background(), "x.y", models.TargetRef{}, nil)
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	svc.Stop()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Stop not bounded: %v", d)
	}
	if got := svc.Counters().Dropped; got != 3 {
		t.Fatalf("dropped=%d want 3 (1 in flight + 2 queued)", got)
	}
}

type concSink struct {
	cur, max atomic.Int64
	calls    atomic.Int64
}

func (c *concSink) Stream(context.Context, []models.AuditEvent) error {
	n := c.cur.Add(1)
	for {
		m := c.max.Load()
		if n <= m || c.max.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	c.cur.Add(-1)
	c.calls.Add(1)
	return nil
}
func (c *concSink) Name() string { return "conc" }

func TestSinkConcurrencyBounded(t *testing.T) {
	tests := []struct {
		name      string
		batches   int
		queueSize int
	}{
		{"many batches one worker", 40, 64},
		{"tiny queue drops instead of spawning", 40, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := sinkQueueSize
			sinkQueueSize = tc.queueSize
			defer func() { sinkQueueSize = old }()
			sink := &concSink{}
			svc := NewService(&slowStore{}, Config{BatchSize: 1, FlushInterval: time.Hour, Sinks: []Sink{sink}, BufferSize: 128})
			_ = svc.Start()
			for i := 0; i < tc.batches; i++ {
				svc.EmitAudit(context.Background(), "x.y", models.TargetRef{}, nil)
			}
			svc.Stop()
			if m := sink.max.Load(); m > 1 {
				t.Fatalf("max concurrent Stream calls = %d, want 1", m)
			}
			got := sink.calls.Load() + int64(svc.Counters().SinkFailed)
			if got != int64(tc.batches) {
				t.Fatalf("delivered+dropped=%d want %d", got, tc.batches)
			}
		})
	}
}

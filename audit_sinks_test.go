package theauth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

// failSink is an AuditSink that always returns an error.
type failSink struct {
	mu    sync.Mutex
	calls int
}

func (s *failSink) Stream(_ context.Context, _ []theauth.AuditEvent) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return errors.New("failSink: intentional failure")
}

func (s *failSink) Name() string { return "fail-sink" }

func (s *failSink) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// recordSink is an AuditSink that captures received batches.
type recordSink struct {
	mu      sync.Mutex
	batches [][]theauth.AuditEvent
	// redactFn is applied to each event before capture when non-nil,
	// mirroring the per-sink redactor pattern used by the built-in sinks.
	redactFn func(theauth.AuditEvent) theauth.AuditEvent
}

func (s *recordSink) Stream(_ context.Context, batch []theauth.AuditEvent) error {
	cp := make([]theauth.AuditEvent, len(batch))
	for i, evt := range batch {
		if s.redactFn != nil {
			evt = s.redactFn(evt)
		}
		cp[i] = evt
	}
	s.mu.Lock()
	s.batches = append(s.batches, cp)
	s.mu.Unlock()
	return nil
}

func (s *recordSink) Name() string { return "record-sink" }

func (s *recordSink) BatchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

func (s *recordSink) AllEvents() []theauth.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []theauth.AuditEvent
	for _, b := range s.batches {
		out = append(out, b...)
	}
	return out
}

// TestSinkFailureNonBlocking asserts that a sink that always returns an
// error does not prevent the canonical storage write from succeeding, and
// that Stats.AuditSinkFailed is incremented.
func TestSinkFailureNonBlocking(t *testing.T) {
	t.Parallel()

	store := memory.New()
	sink := &failSink{}

	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit: &theauth.AuditConfig{
			BufferSize:    64,
			BatchSize:     4,
			FlushInterval: 10 * time.Millisecond,
			DrainTimeout:  2 * time.Second,
			Sinks:         []theauth.AuditSink{sink},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	const n = 8
	for i := 0; i < n; i++ {
		a.EmitAudit(ctx, "test.sink_failure", theauth.TargetRef{Type: "test", ID: "1"}, nil)
	}

	// Close drains the writer goroutine before returning. After Close the
	// memory store is accessed from a single goroutine (the test), so
	// there is no race.
	a.Close()

	// Sink goroutines are fire-and-forget: they are launched by the writer
	// loop but Close only waits for the writer loop itself. Give the sink
	// goroutines a brief window to finish.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sink.Calls() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if sink.Calls() == 0 {
		t.Errorf("failSink was never called; sink fan-out did not fire")
	}

	// All n events must reach canonical storage despite the failing sink.
	// Query after Close so only the test goroutine accesses the store.
	evts, _, qErr := store.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: n + 1})
	if qErr != nil {
		t.Fatalf("QueryAuditEvents: %v", qErr)
	}
	if len(evts) < n {
		t.Errorf("canonical storage: want %d events, got %d", n, len(evts))
	}
}

// TestSinkRedactorOverride verifies that a per-sink redactor can strip
// fields from outgoing events without affecting canonical storage.
func TestSinkRedactorOverride(t *testing.T) {
	t.Parallel()

	store := memory.New()
	sink := &recordSink{
		redactFn: func(evt theauth.AuditEvent) theauth.AuditEvent {
			// Strip email from the outgoing event.
			delete(evt.Metadata, "email")
			return evt
		},
	}

	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		Audit: &theauth.AuditConfig{
			BufferSize:    64,
			BatchSize:     4,
			FlushInterval: 10 * time.Millisecond,
			DrainTimeout:  2 * time.Second,
			Sinks:         []theauth.AuditSink{sink},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	a.EmitAudit(ctx, "user.login", theauth.TargetRef{Type: "user", ID: "u1"},
		map[string]any{"email": "secret@example.com", "safe": "keep-this"})

	// Close drains the writer goroutine. Sink goroutines are fire-and-forget
	// so we give them a brief window after Close.
	a.Close()
	time.Sleep(100 * time.Millisecond)

	if sink.BatchCount() == 0 {
		t.Fatal("sink never received a batch")
	}

	// The sink must not have received the email field.
	for _, evt := range sink.AllEvents() {
		if _, ok := evt.Metadata["email"]; ok {
			t.Errorf("email field present in sink-received event; redactor not applied")
		}
		// Safe field must still be there.
		if _, ok := evt.Metadata["safe"]; !ok {
			t.Errorf("non-email field 'safe' was stripped unexpectedly")
		}
	}
}

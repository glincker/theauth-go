package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// blockingStore holds InsertAuditEvents until released so the buffer can be
// filled deterministically.
type blockingStore struct {
	mu      sync.Mutex
	release chan struct{}
	events  []models.AuditEvent
}

func (b *blockingStore) InsertAuditEvents(_ context.Context, evs []models.AuditEvent) error {
	<-b.release
	b.mu.Lock()
	b.events = append(b.events, evs...)
	b.mu.Unlock()
	return nil
}

func (b *blockingStore) QueryAuditEvents(context.Context, models.AuditQuery) ([]models.AuditEvent, string, error) {
	return nil, "", nil
}

func (b *blockingStore) snapshot() []models.AuditEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]models.AuditEvent(nil), b.events...)
}

func fillAndDrop(t *testing.T, cfg Config) (*Service, *blockingStore, int) {
	t.Helper()
	st := &blockingStore{release: make(chan struct{})}
	cfg.BufferSize = 2
	cfg.BatchSize = 1
	cfg.FlushInterval = time.Hour
	s := NewService(st, cfg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	// The writer takes one event and blocks in Insert; two more fill the buffer.
	for i := 0; i < 3; i++ {
		s.Emit(context.Background(), "user.login", models.TargetRef{}, nil, nil, nil)
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 5; i++ {
		s.Emit(context.Background(), "user.login", models.TargetRef{}, nil, nil, nil)
	}
	return s, st, int(s.Counters().Dropped)
}

func TestDroppedEventsLeaveCountedGapMarker(t *testing.T) {
	s, st, dropped := fillAndDrop(t, Config{})
	if dropped == 0 {
		t.Fatal("expected drops with a full buffer")
	}
	close(st.release)
	s.Stop()

	var markers int
	var total uint64
	for _, e := range st.snapshot() {
		if e.Action == GapMarkerAction {
			markers++
			n, _ := e.Metadata["dropped"].(uint64)
			total += n
		}
	}
	if markers == 0 {
		t.Fatalf("no gap marker among %d events", len(st.snapshot()))
	}
	if total != uint64(dropped) {
		t.Fatalf("markers account for %d dropped events, want %d", total, dropped)
	}
	if c := s.Counters(); c.Dropped != uint64(dropped) {
		t.Fatalf("Dropped counter = %d, want %d", c.Dropped, dropped)
	}
}

func TestEmitDecisionFailsClosedOnlyWhenOptedIn(t *testing.T) {
	s, st, _ := fillAndDrop(t, Config{FailClosed: true})
	err := s.EmitDecision(context.Background(), "approval.decided", models.TargetRef{}, nil, nil, nil)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("decision event err = %v, want ErrAuditUnavailable", err)
	}
	if err := s.EmitDecision(context.Background(), "user.login", models.TargetRef{}, nil, nil, nil); err != nil {
		t.Fatalf("non-decision event must not fail closed: %v", err)
	}
	close(st.release)
	s.Stop()

	open, st2, _ := fillAndDrop(t, Config{})
	if err := open.EmitDecision(context.Background(), "approval.decided", models.TargetRef{}, nil, nil, nil); err != nil {
		t.Fatalf("default config must not fail closed: %v", err)
	}
	close(st2.release)
	open.Stop()
}

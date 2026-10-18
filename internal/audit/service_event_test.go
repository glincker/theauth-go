package audit

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// captureStore records inserted events and answers queries with nothing.
type captureStore struct {
	mu     sync.Mutex
	events []models.AuditEvent
}

func (c *captureStore) InsertAuditEvents(_ context.Context, evs []models.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evs...)
	return nil
}

func (c *captureStore) QueryAuditEvents(context.Context, models.AuditQuery) ([]models.AuditEvent, string, error) {
	return nil, "", nil
}

// emitAndCollect emits each action through a running Service and returns the stored events by action.
func emitAndCollect(t *testing.T, actions []string, ctx context.Context) map[string]models.AuditEvent {
	t.Helper()
	st := &captureStore{}
	s := NewService(st, Config{BatchSize: 1000, FlushInterval: 10 * time.Millisecond})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		s.Emit(ctx, a, models.TargetRef{Type: "t", ID: "1"}, nil, nil, nil)
	}
	s.Stop()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := map[string]models.AuditEvent{}
	for _, e := range st.events {
		out[e.Action] = e
	}
	if len(out) != len(actions) {
		t.Fatalf("stored %d distinct actions, want %d", len(out), len(actions))
	}
	return out
}

func TestEmitSetsEventFromAction(t *testing.T) {
	t.Parallel()
	mapped := ActionEvents()
	actions := []string{"user.login", "agent.suspended", "approval.decided", "policy.denied", "vault.token.denied"}
	for a := range mapped {
		if a != GapMarkerAction { // the gap marker is written by the service itself, covered below
			actions = append(actions, a)
		}
	}
	sort.Strings(actions)
	got := emitAndCollect(t, actions, context.Background())
	for _, a := range actions {
		t.Run("action "+a, func(t *testing.T) {
			if want := EventForAction(a); got[a].Event != want {
				t.Fatalf("Event = %q, want %q", got[a].Event, want)
			}
		})
	}
}

// TestEveryScannedActionGetsExpectedEvent covers every action string the repo writes (the source
// scan from events_test.go): mapped ones end up with their event, the rest with none.
func TestEveryScannedActionGetsExpectedEvent(t *testing.T) {
	t.Parallel()
	found := scanWrittenActions(t)
	actions := make([]string, 0, len(found))
	for a := range found {
		if a == GapMarkerAction {
			continue
		}
		actions = append(actions, a)
	}
	sort.Strings(actions)
	got := emitAndCollect(t, actions, context.Background())
	for _, a := range actions {
		want, mapped := actionEvents[a]
		if !mapped {
			want = ""
		}
		if got[a].Event != want {
			t.Errorf("action %q: Event = %q, want %q", a, got[a].Event, want)
		}
		if err := ValidateEvent(got[a].Event); err != nil {
			t.Errorf("action %q: %v", a, err)
		}
	}
}

func TestEmitExplicitEventFromMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		action string
		event  string
		want   string
	}{
		{"valid event wins over the mapping", "approval.decided", EventApprovalApprove, EventApprovalApprove},
		{"valid event on an unmapped action", "custom.thing", EventMCPToolCall, EventMCPToolCall},
		{"unknown event is ignored in favour of the mapping", "agent.created", "made.up", EventAgentCreate},
		{"unknown event on an unmapped action stays empty", "custom.thing", "made.up", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithAuditMetadata(context.Background(), AuditMetadata{Event: tc.event})
			got := emitAndCollect(t, []string{tc.action}, ctx)
			if got[tc.action].Event != tc.want {
				t.Fatalf("Event = %q, want %q", got[tc.action].Event, tc.want)
			}
		})
	}
}

func TestGapMarkerCarriesWriteFailedEvent(t *testing.T) {
	t.Parallel()
	s := NewService(&captureStore{}, Config{})
	s.dropped.Store(3)
	if got := s.gapMarker(3).Event; got != EventAuditWriteFailed {
		t.Fatalf("gap marker Event = %q, want %q", got, EventAuditWriteFailed)
	}
}

// legacyOnly hides AuditOrderSupported, like a custom backend written before write order existed.
type legacyOnly struct{ Storage }

type withOrder struct{ Storage }

func (withOrder) AuditOrderSupported() bool { return true }

type orderDisabled struct{ Storage }

func (orderDisabled) AuditOrderSupported() bool { return false }

func TestCheckQuery(t *testing.T) {
	t.Parallel()
	ascCursor := EncodeCursor(Cursor{RecordedAtUs: 5, ID: models.ULID{1}, Order: models.AuditOrderAsc})
	descCursor := EncodeCursor(Cursor{RecordedAtUs: 5, ID: models.ULID{1}, Order: models.AuditOrderDesc})
	base := &captureStore{}
	tests := []struct {
		name    string
		store   Storage
		q       models.AuditQuery
		wantErr error
	}{
		{"default desc on a legacy backend", legacyOnly{base}, models.AuditQuery{}, nil},
		{"explicit desc on a legacy backend", legacyOnly{base}, models.AuditQuery{Order: "desc"}, nil},
		{"legacy cursor on a legacy backend", legacyOnly{base}, models.AuditQuery{After: "bGVnYWN5"}, nil},
		{"asc on a legacy backend", legacyOnly{base}, models.AuditQuery{Order: "asc"}, models.ErrAuditOrderUnsupported},
		{"event filter on a legacy backend", legacyOnly{base}, models.AuditQuery{Event: EventAuthorize}, models.ErrAuditOrderUnsupported},
		{"asc on a backend that reports false", orderDisabled{base}, models.AuditQuery{Order: "asc"}, models.ErrAuditOrderUnsupported},
		{"c1 cursor on a legacy backend", legacyOnly{base}, models.AuditQuery{After: descCursor}, models.ErrAuditOrderUnsupported},
		{"asc on a capable backend", withOrder{base}, models.AuditQuery{Order: "asc"}, nil},
		{"event filter on a capable backend", withOrder{base}, models.AuditQuery{Event: EventAuthorize}, nil},
		{"asc cursor continues asc", withOrder{base}, models.AuditQuery{Order: "asc", After: ascCursor}, nil},
		{"desc cursor continues default order", withOrder{base}, models.AuditQuery{After: descCursor}, nil},
		{"asc cursor rejected for desc", withOrder{base}, models.AuditQuery{After: ascCursor}, models.ErrBadCursor},
		{"desc cursor rejected for asc", withOrder{base}, models.AuditQuery{Order: "asc", After: descCursor}, models.ErrBadCursor},
		{"garbage c1 cursor", withOrder{base}, models.AuditQuery{After: "c1.zzzz"}, models.ErrBadCursor},
		{"legacy cursor rejected for asc", withOrder{base}, models.AuditQuery{Order: "asc", After: "bGVnYWN5"}, models.ErrBadCursor},
		{"unknown order", withOrder{base}, models.AuditQuery{Order: "sideways"}, models.ErrBadAuditOrder},
		{"unknown order on a legacy backend", legacyOnly{base}, models.AuditQuery{Order: "ASC"}, models.ErrBadAuditOrder},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckQuery(tc.store, tc.q)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("CheckQuery = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestServiceQueryRejectsUnsupportedOrder(t *testing.T) {
	t.Parallel()
	s := NewService(legacyOnly{&captureStore{}}, Config{})
	if _, _, err := s.Query(context.Background(), models.AuditQuery{Order: "asc"}); !errors.Is(err, models.ErrAuditOrderUnsupported) {
		t.Fatalf("Query asc = %v, want ErrAuditOrderUnsupported", err)
	}
	if _, _, err := s.Query(context.Background(), models.AuditQuery{}); err != nil {
		t.Fatalf("Query default = %v", err)
	}
}

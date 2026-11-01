package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

func TestTargetMatches(t *testing.T) {
	target := Target{UserID: "u1", SessionID: "s1", TokenID: "t1", AgentID: "a1", CredentialID: "c1", DelegationID: "d1", OrganizationID: "o1"}
	tests := []struct {
		name string
		ev   Event
		want bool
	}{
		{"session by id", Event{Kind: Session, ID: "s1"}, true},
		{"other session", Event{Kind: Session, ID: "s2"}, false},
		{"all sessions of user", Event{Kind: Session, UserID: "u1"}, true},
		{"all sessions of other user", Event{Kind: Session, UserID: "u2"}, false},
		{"token by id", Event{Kind: APIToken, ID: "t1"}, true},
		{"owner", Event{Kind: Owner, UserID: "u1"}, true},
		{"owner empty user", Event{Kind: Owner}, false},
		{"agent", Event{Kind: Agent, ID: "a1"}, true},
		{"agent no id", Event{Kind: Agent, UserID: "u1"}, false},
		{"credential", Event{Kind: AgentCredential, ID: "c1"}, true},
		{"delegation", Event{Kind: Delegation, ID: "d1"}, true},
		{"org member match", Event{Kind: OrgMember, ID: "o1", UserID: "u1"}, true},
		{"org member other org", Event{Kind: OrgMember, ID: "o2", UserID: "u1"}, false},
		{"org member other user", Event{Kind: OrgMember, ID: "o1", UserID: "u2"}, false},
		{"unknown kind", Event{Kind: "bogus", ID: "s1"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := target.Matches(tc.ev); got != tc.want {
				t.Fatalf("Matches(%+v) = %v, want %v", tc.ev, got, tc.want)
			}
		})
	}
	if (Target{}).Matches(Event{Kind: Session, ID: ""}) {
		t.Fatal("empty target must not match an empty-id event")
	}
}

func TestMemoryBusPublishSubscribe(t *testing.T) {
	bus := NewMemoryBus()
	var got []Event
	unsub, err := bus.Subscribe(func(ev Event) { got = append(got, ev) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bus.Subscribe(func(Event) { panic("boom") }); err != nil {
		t.Fatal(err)
	}
	if err := Publish(context.Background(), bus, Event{Kind: Agent, ID: "a1"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].At.IsZero() {
		t.Fatalf("subscriber must run despite a panicking peer and At must be stamped: %+v", got)
	}
	unsub()
	PublishQuiet(context.Background(), bus, Event{Kind: Agent, ID: "a2"})
	if len(got) != 1 {
		t.Fatalf("unsubscribed fn still called: %+v", got)
	}
	if _, err := bus.Subscribe(nil); err == nil {
		t.Fatal("nil subscriber must be rejected")
	}
}

type failBus struct{}

func (failBus) Publish(context.Context, Event) error  { return errors.New("down") }
func (failBus) Subscribe(func(Event)) (func(), error) { return nil, errors.New("down") }

func TestPublishWrapsBusError(t *testing.T) {
	if err := Publish(context.Background(), failBus{}, Event{}); err == nil {
		t.Fatal("want error")
	}
	PublishQuiet(context.Background(), failBus{}, Event{Kind: Session})
}

func TestWatchCancelsOnMatchingEvent(t *testing.T) {
	bus := NewMemoryBus()
	w := Watcher{Bus: bus}
	ctx, cancel := w.Watch(context.Background(), Target{SessionID: "s1"}, WatchOptions{})
	defer cancel(nil)

	_ = bus.Publish(context.Background(), Event{Kind: Session, ID: "other"})
	select {
	case <-ctx.Done():
		t.Fatal("unrelated event cancelled the watch")
	case <-time.After(20 * time.Millisecond):
	}
	_ = bus.Publish(context.Background(), Event{Kind: Session, ID: "s1", Reason: "session.revoked"})
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("matching event did not cancel")
	}
	if !errors.Is(context.Cause(ctx), models.ErrCredentialRevoked) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
}

func TestWatchSubscribeFailureCancels(t *testing.T) {
	ctx, cancel := Watcher{Bus: failBus{}}.Watch(context.Background(), Target{}, WatchOptions{})
	defer cancel(nil)
	if ctx.Err() == nil {
		t.Fatal("subscribe failure must cancel the context")
	}
}

func TestWatchPollsBearer(t *testing.T) {
	w := Watcher{Bus: NewMemoryBus(), CheckBearer: func(context.Context, string) error { return models.ErrCredentialRevoked }}
	ctx, cancel := w.Watch(context.Background(), Target{}, WatchOptions{PollInterval: 5 * time.Millisecond, BearerToken: "raw"})
	defer cancel(nil)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("bearer poll did not cancel")
	}
	if !errors.Is(context.Cause(ctx), models.ErrCredentialRevoked) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
}

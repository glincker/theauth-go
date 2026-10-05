// Package revocation carries credential revocation events, the bus that
// fans them out, and the watcher that cancels a context when one matches.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Kind says what was revoked.
type Kind string

// Revocation kinds.
const (
	Session         Kind = "session"
	APIToken        Kind = "api_token"
	Agent           Kind = "agent"
	AgentCredential Kind = "agent_credential"
	Delegation      Kind = "delegation"
	// Owner means a user was disabled or deleted: every credential
	// that user owns or delegated is void.
	Owner Kind = "owner"
)

// Event reports one revocation. An empty ID means "every credential
// of this kind belonging to UserID".
type Event struct {
	Kind   Kind      `json:"kind"`
	ID     string    `json:"id,omitempty"`
	UserID string    `json:"userId,omitempty"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// Bus fans revocation events out to subscribers. The default is
// in-process; implement it over Postgres NOTIFY or Redis pub/sub so a
// revocation on one node reaches streams held by another.
type Bus interface {
	// Publish delivers ev to every subscriber, local and remote.
	Publish(ctx context.Context, ev Event) error
	// Subscribe registers fn and returns a func that removes it. fn must not
	// block: it runs on the publisher's or listener's goroutine.
	Subscribe(fn func(Event)) (unsubscribe func(), err error)
}

// MemoryBus is the in-process Bus.
type MemoryBus struct {
	mu   sync.RWMutex
	next int
	subs map[int]func(Event)
}

// NewMemoryBus returns an empty in-process bus.
func NewMemoryBus() *MemoryBus {
	return &MemoryBus{subs: map[int]func(Event){}}
}

// Publish calls every subscriber synchronously, isolating panics.
func (b *MemoryBus) Publish(_ context.Context, ev Event) error {
	b.mu.RLock()
	fns := make([]func(Event), 0, len(b.subs))
	for _, fn := range b.subs {
		fns = append(fns, fn)
	}
	b.mu.RUnlock()
	for _, fn := range fns {
		callFn(fn, ev)
	}
	return nil
}

// Subscribe registers fn.
func (b *MemoryBus) Subscribe(fn func(Event)) (func(), error) {
	if fn == nil {
		return nil, errors.New("theauth: nil revocation subscriber")
	}
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = fn
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
	}, nil
}

func callFn(fn func(Event), ev Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("theauth: revocation subscriber panicked", "panic", r)
		}
	}()
	fn(ev)
}

// Publish sends ev on bus, stamping At when zero.
func Publish(ctx context.Context, bus Bus, ev Event) error {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if err := bus.Publish(ctx, ev); err != nil {
		return fmt.Errorf("theauth: publish revocation: %w", err)
	}
	return nil
}

// PublishQuiet publishes ev and logs, rather than returns, a delivery failure.
func PublishQuiet(ctx context.Context, bus Bus, ev Event) {
	if err := Publish(ctx, bus, ev); err != nil {
		slog.Warn("theauth: revocation not delivered", "kind", string(ev.Kind), "err", err.Error())
	}
}

// FromAudit maps audit actions that void a credential to events, so every
// internal revoke path reaches the bus without per-site wiring. It reports
// false for actions that revoke nothing.
func FromAudit(action string, target models.TargetRef, md map[string]any) (Event, bool) {
	ev := Event{Reason: action}
	switch action {
	case "session.revoked":
		ev.Kind = Session
		if target.Type == "user" {
			ev.UserID = target.ID
		} else {
			ev.ID = target.ID
		}
	case "delegation.revoked":
		ev.Kind, ev.ID = Delegation, target.ID
	case "agent.revoked", "agent.suspended":
		ev.Kind, ev.ID = Agent, target.ID
	case "agent_credential.revoked":
		id, _ := md["credential_id"].(string)
		if id == "" {
			return Event{}, false
		}
		ev.Kind, ev.ID = AgentCredential, id
	default:
		return Event{}, false
	}
	return ev, true
}

// Target names the credential a stream was opened with. Set every
// ID that applies; an event matches when it names any of them.
type Target struct {
	UserID       string
	SessionID    string
	TokenID      string
	AgentID      string
	CredentialID string
	DelegationID string
}

// Matches reports whether ev voids the target.
func (t Target) Matches(ev Event) bool {
	pick := func(want string) bool {
		if ev.ID != "" {
			return want != "" && ev.ID == want
		}
		return ev.UserID != "" && ev.UserID == t.UserID
	}
	switch ev.Kind {
	case Session:
		return pick(t.SessionID)
	case APIToken:
		return pick(t.TokenID)
	case Owner:
		return ev.UserID != "" && ev.UserID == t.UserID
	case Agent:
		return ev.ID != "" && ev.ID == t.AgentID
	case AgentCredential:
		return ev.ID != "" && ev.ID == t.CredentialID
	case Delegation:
		return ev.ID != "" && ev.ID == t.DelegationID
	}
	return false
}

// WatchOptions tunes a revocation watch.
type WatchOptions struct {
	// PollInterval, when positive, also re-validates SessionToken or
	// BearerToken on a timer, a backstop for a bus that missed an event
	// (a remote node, a dropped NOTIFY). Sessions reuse WatchSession.
	PollInterval time.Duration
	// SessionToken is the raw session token to poll.
	SessionToken string
	// BearerToken is the raw API token to poll.
	BearerToken string
}

// Watcher supplies the credential re-validation a watch polls with.
type Watcher struct {
	Bus Bus
	// WatchSession returns a context cancelled when the session dies; nil when sessions are unavailable.
	WatchSession func(ctx context.Context, token string, every time.Duration) (context.Context, context.CancelCauseFunc)
	// CheckBearer re-validates a raw API token; nil when API tokens are off.
	CheckBearer func(ctx context.Context, raw string) error
}

// Watch returns a context cancelled, with an error wrapping
// models.ErrCredentialRevoked as its cause, as soon as an event matches target
// or a poll finds the credential invalid. Call the cancel func when the stream ends.
func (w Watcher) Watch(ctx context.Context, target Target, opts WatchOptions) (context.Context, context.CancelCauseFunc) {
	var cancel context.CancelCauseFunc
	if opts.SessionToken != "" && opts.PollInterval > 0 && w.WatchSession != nil {
		ctx, cancel = w.WatchSession(ctx, opts.SessionToken, opts.PollInterval)
	} else {
		ctx, cancel = context.WithCancelCause(ctx)
	}
	unsub, err := w.Bus.Subscribe(func(ev Event) {
		if target.Matches(ev) {
			cancel(fmt.Errorf("%w: %s %s", models.ErrCredentialRevoked, ev.Kind, ev.Reason))
		}
	})
	if err != nil {
		cancel(fmt.Errorf("theauth: subscribe revocations: %w", err))
		return ctx, cancel
	}
	if opts.BearerToken != "" && opts.PollInterval > 0 && w.CheckBearer != nil {
		go w.pollBearer(ctx, opts, cancel)
	}
	go func() {
		<-ctx.Done()
		unsub()
	}()
	return ctx, cancel
}

func (w Watcher) pollBearer(ctx context.Context, opts WatchOptions, cancel context.CancelCauseFunc) {
	t := time.NewTicker(opts.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.CheckBearer(ctx, opts.BearerToken); err != nil {
				if ctx.Err() == nil {
					cancel(fmt.Errorf("%w: %w", models.ErrCredentialRevoked, err))
				}
				return
			}
		}
	}
}

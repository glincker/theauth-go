package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RevocationKind says what was revoked.
type RevocationKind string

// Revocation kinds.
const (
	RevocationSession         RevocationKind = "session"
	RevocationAPIToken        RevocationKind = "api_token"
	RevocationAgent           RevocationKind = "agent"
	RevocationAgentCredential RevocationKind = "agent_credential"
	RevocationDelegation      RevocationKind = "delegation"
	// RevocationOwner means a user was disabled or deleted: every credential
	// that user owns or delegated is void.
	RevocationOwner RevocationKind = "owner"
)

// RevocationEvent reports one revocation. An empty ID means "every credential
// of this kind belonging to UserID".
type RevocationEvent struct {
	Kind   RevocationKind `json:"kind"`
	ID     string         `json:"id,omitempty"`
	UserID string         `json:"userId,omitempty"`
	Reason string         `json:"reason,omitempty"`
	At     time.Time      `json:"at"`
}

// RevocationBus fans revocation events out to subscribers. The default is
// in-process; implement it over Postgres NOTIFY or Redis pub/sub so a
// revocation on one node reaches streams held by another.
type RevocationBus interface {
	// Publish delivers ev to every subscriber, local and remote.
	Publish(ctx context.Context, ev RevocationEvent) error
	// Subscribe registers fn and returns a func that removes it. fn must not
	// block: it runs on the publisher's or listener's goroutine.
	Subscribe(fn func(RevocationEvent)) (unsubscribe func(), err error)
}

// MemoryRevocationBus is the in-process RevocationBus.
type MemoryRevocationBus struct {
	mu   sync.RWMutex
	next int
	subs map[int]func(RevocationEvent)
}

// NewMemoryRevocationBus returns an empty in-process bus.
func NewMemoryRevocationBus() *MemoryRevocationBus {
	return &MemoryRevocationBus{subs: map[int]func(RevocationEvent){}}
}

// Publish calls every subscriber synchronously, isolating panics.
func (b *MemoryRevocationBus) Publish(_ context.Context, ev RevocationEvent) error {
	b.mu.RLock()
	fns := make([]func(RevocationEvent), 0, len(b.subs))
	for _, fn := range b.subs {
		fns = append(fns, fn)
	}
	b.mu.RUnlock()
	for _, fn := range fns {
		callRevocationFn(fn, ev)
	}
	return nil
}

// Subscribe registers fn.
func (b *MemoryRevocationBus) Subscribe(fn func(RevocationEvent)) (func(), error) {
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

func callRevocationFn(fn func(RevocationEvent), ev RevocationEvent) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("theauth: revocation subscriber panicked", "panic", r)
		}
	}()
	fn(ev)
}

func (a *TheAuth) revocationBus() RevocationBus { return a.revocations }

// PublishRevocation sends ev on the revocation bus, stamping At when zero.
func (a *TheAuth) PublishRevocation(ctx context.Context, ev RevocationEvent) error {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if err := a.revocationBus().Publish(ctx, ev); err != nil {
		return fmt.Errorf("theauth: publish revocation: %w", err)
	}
	return nil
}

func (a *TheAuth) publishRevocation(ctx context.Context, ev RevocationEvent) {
	if err := a.PublishRevocation(ctx, ev); err != nil {
		slog.Warn("theauth: revocation not delivered", "kind", string(ev.Kind), "err", err.Error())
	}
}

// SubscribeRevocations registers fn for every revocation event.
func (a *TheAuth) SubscribeRevocations(fn func(RevocationEvent)) (func(), error) {
	return a.revocationBus().Subscribe(fn)
}

// NotifyOwnerDisabled tells watchers that a user was disabled or deleted. The
// library cannot see host-side disable flags, so the host calls this when it
// flips them (the same flag Config.APITokens.OwnerActive reads).
func (a *TheAuth) NotifyOwnerDisabled(ctx context.Context, userID ULID, reason string) error {
	return a.PublishRevocation(ctx, RevocationEvent{Kind: RevocationOwner, UserID: userID.String(), Reason: reason})
}

// revocationFromAudit maps audit actions that void a credential to events, so
// every internal revoke path reaches the bus without per-site wiring.
func (a *TheAuth) revocationFromAudit(ctx context.Context, action string, target TargetRef, md map[string]any) {
	ev := RevocationEvent{Reason: action}
	switch action {
	case "session.revoked":
		ev.Kind = RevocationSession
		if target.Type == "user" {
			ev.UserID = target.ID
		} else {
			ev.ID = target.ID
		}
	case "delegation.revoked":
		ev.Kind, ev.ID = RevocationDelegation, target.ID
	case "agent.revoked", "agent.suspended":
		ev.Kind, ev.ID = RevocationAgent, target.ID
	case "agent_credential.revoked":
		id, _ := md["credential_id"].(string)
		if id == "" {
			return
		}
		ev.Kind, ev.ID = RevocationAgentCredential, id
	default:
		return
	}
	a.publishRevocation(ctx, ev)
}

// RevocationTarget names the credential a stream was opened with. Set every
// ID that applies; an event matches when it names any of them.
type RevocationTarget struct {
	UserID       string
	SessionID    string
	TokenID      string
	AgentID      string
	CredentialID string
	DelegationID string
}

// Matches reports whether ev voids the target.
func (t RevocationTarget) Matches(ev RevocationEvent) bool {
	pick := func(want string) bool {
		if ev.ID != "" {
			return want != "" && ev.ID == want
		}
		return ev.UserID != "" && ev.UserID == t.UserID
	}
	switch ev.Kind {
	case RevocationSession:
		return pick(t.SessionID)
	case RevocationAPIToken:
		return pick(t.TokenID)
	case RevocationOwner:
		return ev.UserID != "" && ev.UserID == t.UserID
	case RevocationAgent:
		return ev.ID != "" && ev.ID == t.AgentID
	case RevocationAgentCredential:
		return ev.ID != "" && ev.ID == t.CredentialID
	case RevocationDelegation:
		return ev.ID != "" && ev.ID == t.DelegationID
	}
	return false
}

// WatchOptions tunes WatchRevocation.
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

// WatchRevocation returns a context cancelled, with an error wrapping
// ErrCredentialRevoked as its cause, as soon as an event matches target or a
// poll finds the credential invalid. Call the cancel func when the stream ends.
func (a *TheAuth) WatchRevocation(ctx context.Context, target RevocationTarget, opts WatchOptions) (context.Context, context.CancelCauseFunc) {
	var cancel context.CancelCauseFunc
	if opts.SessionToken != "" && opts.PollInterval > 0 && a.sessionSvc != nil {
		ctx, cancel = a.WatchSession(ctx, opts.SessionToken, opts.PollInterval)
	} else {
		ctx, cancel = context.WithCancelCause(ctx)
	}
	unsub, err := a.SubscribeRevocations(func(ev RevocationEvent) {
		if target.Matches(ev) {
			cancel(fmt.Errorf("%w: %s %s", ErrCredentialRevoked, ev.Kind, ev.Reason))
		}
	})
	if err != nil {
		cancel(fmt.Errorf("theauth: subscribe revocations: %w", err))
		return ctx, cancel
	}
	if opts.BearerToken != "" && opts.PollInterval > 0 && a.apiTokens != nil {
		go a.pollBearer(ctx, opts, cancel)
	}
	go func() {
		<-ctx.Done()
		unsub()
	}()
	return ctx, cancel
}

func (a *TheAuth) pollBearer(ctx context.Context, opts WatchOptions, cancel context.CancelCauseFunc) {
	t := time.NewTicker(opts.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.apiTokens.authenticate(ctx, opts.BearerToken); err != nil {
				if ctx.Err() == nil {
					cancel(fmt.Errorf("%w: %w", ErrCredentialRevoked, err))
				}
				return
			}
		}
	}
}

// TargetForPrincipal builds the watch target for an authenticated principal.
func TargetForPrincipal(p *Principal) RevocationTarget {
	t := RevocationTarget{UserID: p.UserID.String()}
	if p.TokenID != nil {
		t.TokenID = p.TokenID.String()
	}
	return t
}

// WatchRevocationMiddleware cancels the request context when the presented
// credential is revoked, so SSE, MCP and other long-lived handlers drop within
// seconds. Place it after RequireAbility, which supplies the Principal; a
// session cookie is used when no bearer token was presented.
func (a *TheAuth) WatchRevocationMiddleware(opts WatchOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			target := TargetForPrincipal(p)
			o := opts
			o.SessionToken, o.BearerToken = "", ""
			if raw, ok := bearerToken(r); ok && p.TokenID != nil {
				o.BearerToken = raw
			} else if c, err := r.Cookie(a.cookieName); err == nil && c.Value != "" {
				o.SessionToken = c.Value
				if sess, _, err := a.validateSession(r.Context(), c.Value); err == nil {
					target.SessionID = sess.ID.String()
				}
			}
			if strings.TrimSpace(o.BearerToken) == "" && o.SessionToken == "" && p.TokenID == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := a.WatchRevocation(r.Context(), target, o)
			defer cancel(nil)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

package signals

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// Handler reacts to one verified event.
type Handler interface {
	HandleEvent(ctx context.Context, set *SET, ev Event) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, set *SET, ev Event) error

// HandleEvent implements Handler.
func (f HandlerFunc) HandleEvent(ctx context.Context, set *SET, ev Event) error {
	return f(ctx, set, ev)
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	// Audience is this receiver's identifier. The SET aud must contain it.
	Audience string
	// Issuers are the transmitters this receiver trusts. The key is the iss
	// value; the value is an optional jwks_uri that skips SSF discovery.
	Issuers map[string]string
	// Authenticate, when set, must approve the push request (for example by
	// checking the bearer token configured on the stream).
	Authenticate func(r *http.Request) bool
	// Handlers run for every verified event, in order.
	Handlers []Handler

	AllowPrivateNetworks bool
	AllowInsecureHTTP    bool
	Lookup               func(ctx context.Context, host string) ([]netip.Addr, error)
	HTTPClient           *http.Client

	// JWKSTTL is how long fetched keys are trusted. Default 10m.
	JWKSTTL time.Duration
	// JWKSRefetchCooldown limits kid-miss refetches. Default 30s.
	JWKSRefetchCooldown time.Duration
	// ReplayWindow is how long a jti is remembered. Default 24h.
	ReplayWindow time.Duration
	// MaxReplayEntries bounds the replay cache. Default 100000; when full the
	// oldest expired entries go first and, failing that, new SETs are refused.
	MaxReplayEntries int
	// MaxAge rejects SETs older than this. Default 0 (no age bound).
	MaxAge time.Duration

	Clock  func() time.Time
	Logger *slog.Logger
}

// Receive error codes (RFC 8935 section 2.4).
const (
	CodeInvalidRequest  = "invalid_request"
	CodeInvalidKey      = "invalid_key"
	CodeInvalidIssuer   = "invalid_issuer"
	CodeInvalidAudience = "invalid_audience"
	CodeAuthFailed      = "authentication_failed"
	CodeAccessDenied    = "access_denied"
)

// ReceiveError is a SET rejection with an RFC 8935 error code.
type ReceiveError struct {
	Code        string
	Description string
	Err         error
}

func (e *ReceiveError) Error() string {
	return fmt.Sprintf("signals: %s: %s", e.Code, e.Description)
}

// Unwrap exposes the cause.
func (e *ReceiveError) Unwrap() error { return e.Err }

// ErrReplay is wrapped by the ReceiveError of a replayed SET.
var ErrReplay = errors.New("signals: SET already processed")

// Receiver verifies and dispatches incoming SETs.
type Receiver struct {
	cfg  ReceiverConfig
	jwks *jwksCache
	log  *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewReceiver validates cfg and builds a Receiver.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if cfg.Audience == "" {
		return nil, errors.New("signals: ReceiverConfig.Audience is required")
	}
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("signals: ReceiverConfig.Issuers must list at least one trusted issuer")
	}
	if cfg.JWKSTTL <= 0 {
		cfg.JWKSTTL = 10 * time.Minute
	}
	if cfg.JWKSRefetchCooldown <= 0 {
		cfg.JWKSRefetchCooldown = 30 * time.Second
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 24 * time.Hour
	}
	if cfg.MaxReplayEntries <= 0 {
		cfg.MaxReplayEntries = 100000
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = safehttp.NewClient(10*time.Second, cfg.AllowPrivateNetworks)
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Receiver{
		cfg: cfg, log: lg, seen: map[string]time.Time{},
		jwks: &jwksCache{hc: hc, ttl: cfg.JWKSTTL, cooldown: cfg.JWKSRefetchCooldown, now: cfg.Clock,
			policy:  URLPolicy{AllowPrivate: cfg.AllowPrivateNetworks, AllowHTTP: cfg.AllowInsecureHTTP, Lookup: cfg.Lookup},
			entries: map[string]*jwksEntry{}},
	}, nil
}

// Handle verifies token and dispatches its events. A replayed jti returns a
// ReceiveError wrapping ErrReplay without running handlers again.
func (r *Receiver) Handle(ctx context.Context, token string) (*SET, error) {
	token = strings.TrimSpace(token)
	iss, err := PeekIssuer(token)
	if err != nil {
		return nil, &ReceiveError{Code: CodeInvalidRequest, Description: "malformed SET", Err: err}
	}
	jwksURI, trusted := r.cfg.Issuers[iss]
	if !trusted {
		return nil, &ReceiveError{Code: CodeInvalidIssuer, Description: "issuer is not trusted"}
	}
	resolve, err := r.jwks.resolver(ctx, iss, jwksURI)
	if err != nil {
		return nil, &ReceiveError{Code: CodeInvalidKey, Description: "issuer keys unavailable", Err: err}
	}
	set, err := Verify(token, resolve, VerifyOptions{Issuer: iss, Now: r.cfg.Clock(), MaxAge: r.cfg.MaxAge})
	if err != nil {
		return nil, &ReceiveError{Code: CodeInvalidKey, Description: "SET verification failed", Err: err}
	}
	if !containsStr(set.Audience, r.cfg.Audience) {
		return nil, &ReceiveError{Code: CodeInvalidAudience, Description: "SET is not addressed to this receiver"}
	}
	key := iss + "\x00" + set.JTI
	if err := r.markSeen(key); err != nil {
		if errors.Is(err, ErrReplay) {
			return set, &ReceiveError{Code: CodeInvalidRequest, Description: "SET already processed", Err: err}
		}
		return nil, err
	}
	for _, ev := range set.Events {
		for _, h := range r.cfg.Handlers {
			if err := h.HandleEvent(ctx, set, ev); err != nil {
				r.forget(key)
				return set, fmt.Errorf("signals: handler for %s: %w", ev.Type, err)
			}
		}
	}
	return set, nil
}

func containsStr(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func (r *Receiver) markSeen(key string) error {
	now := r.cfg.Clock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.seen[key]; ok && exp.After(now) {
		return ErrReplay
	}
	if len(r.seen) >= r.cfg.MaxReplayEntries {
		for k, exp := range r.seen {
			if !exp.After(now) {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.cfg.MaxReplayEntries {
			return errors.New("signals: replay cache full")
		}
	}
	r.seen[key] = now.Add(r.cfg.ReplayWindow)
	return nil
}

func (r *Receiver) forget(key string) {
	r.mu.Lock()
	delete(r.seen, key)
	r.mu.Unlock()
}

// ServeHTTP implements the RFC 8935 push endpoint.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, CodeInvalidRequest, "POST required")
		return
	}
	if r.cfg.Authenticate != nil && !r.cfg.Authenticate(req) {
		writeErr(w, http.StatusUnauthorized, CodeAuthFailed, "authentication failed")
		return
	}
	if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/secevent+jwt") {
		writeErr(w, http.StatusBadRequest, CodeInvalidRequest, "Content-Type must be application/secevent+jwt")
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 256<<10))
	if err != nil {
		writeErr(w, http.StatusBadRequest, CodeInvalidRequest, "unreadable body")
		return
	}
	_, err = r.Handle(req.Context(), string(body))
	var re *ReceiveError
	switch {
	case err == nil:
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, ErrReplay):
		// A retried delivery of an already processed SET is a success.
		w.WriteHeader(http.StatusAccepted)
	case errors.As(err, &re):
		r.log.Warn("signals: SET rejected", "code", re.Code, "error", re.Err)
		writeErr(w, http.StatusBadRequest, re.Code, re.Description)
	default:
		r.log.Error("signals: SET processing failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "server_error", "processing failed")
	}
}

// SessionRevocationConfig configures SessionRevocationHandler.
type SessionRevocationConfig struct {
	// ResolveUser maps a subject to a local user id. ok false means the
	// subject is unknown here and the event is ignored.
	ResolveUser func(ctx context.Context, sub Subject) (userID string, ok bool, err error)
	// RevokeSessions revokes every session of userID.
	RevokeSessions func(ctx context.Context, userID string) error
	// Events overrides the handled event types. Default: session-revoked,
	// sessions-revoked, account-disabled.
	Events []string
}

// SessionRevocationHandler is the default Handler: it revokes local sessions
// when a trusted transmitter reports session or account loss.
func SessionRevocationHandler(c SessionRevocationConfig) Handler {
	events := c.Events
	if len(events) == 0 {
		events = []string{EventSessionRevoked, EventSessionsRevoked, EventAccountDisabled}
	}
	return HandlerFunc(func(ctx context.Context, _ *SET, ev Event) error {
		if !containsStr(events, ev.Type) {
			return nil
		}
		sub := ev.Subject
		if u, ok := sub.Complex["user"]; ok {
			sub = u
		}
		if sub.IsZero() || len(sub.Complex) > 0 {
			return nil
		}
		uid, ok, err := c.ResolveUser(ctx, sub)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		return c.RevokeSessions(ctx, uid)
	})
}

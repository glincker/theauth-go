package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/signals"
	oklogulid "github.com/oklog/ulid/v2"
)

// SharedSignalsConfig enables the OpenID Shared Signals Framework 1.0
// transmitter (with CAEP and RISC events) and, optionally, a receiver. See
// docs/shared-signals.md. Nil keeps the feature off and adds no routes, no
// goroutines and no per-event work.
type SharedSignalsConfig struct {
	// Authenticate resolves the calling receiver of the stream management
	// and poll endpoints, typically by validating an access token. It
	// returns a stable receiver id that owns the streams it creates.
	// Required. signals.StaticBearerAuth covers simple setups.
	Authenticate func(r *http.Request) (receiverID string, ok bool)

	// Issuer is the SET issuer. Default: AuthorizationServer.Issuer, which
	// the feature requires (SETs are signed with the AS keys and the JWKS
	// served at /oauth/jwks verifies them).
	Issuer string
	// BaseURL is the public URL the handler is mounted at, used for
	// endpoint URLs in the metadata document. Default: Issuer.
	BaseURL string
	// Store holds streams and the delivery queue. Default: in memory, which
	// loses queued events on restart; use the sqlite or postgres
	// SignalsStore for production.
	Store signals.Store

	// EmitFromAudit emits SSF events from the library's own audit actions
	// (session revoke, sessions revoke, password change, passkey and TOTP
	// changes, account disable and enable). Off by default.
	EmitFromAudit bool
	// SubjectFor builds the subject identifier of a local user. Default is
	// an iss_sub subject with the issuer and the user id.
	SubjectFor signals.SubjectFunc

	// AllowPrivateNetworks and AllowInsecureHTTP relax push URL validation.
	// Leave both false in production.
	AllowPrivateNetworks bool
	AllowInsecureHTTP    bool
	// MaxAttempts, BackoffBase and BackoffMax tune push retry. Defaults 8,
	// 2s and 15m.
	MaxAttempts int
	BackoffBase time.Duration
	BackoffMax  time.Duration

	// Receiver, when non-nil, builds a receiver for incoming SETs.
	Receiver *SharedSignalsReceiverConfig
}

// SharedSignalsReceiverConfig configures the receiver half.
type SharedSignalsReceiverConfig struct {
	// Audience is this receiver's identifier, matched against SET aud.
	Audience string
	// Issuers lists trusted transmitters: iss value to optional jwks_uri.
	Issuers map[string]string
	// Authenticate approves push requests. Strongly recommended.
	Authenticate func(r *http.Request) bool
	// ResolveUser maps a subject to a local user id for the default
	// session revocation handler. Default: email subjects are looked up by
	// address; other formats are ignored.
	ResolveUser func(ctx context.Context, sub signals.Subject) (userID ULID, ok bool, err error)
	// Handlers run after the default revocation handler.
	Handlers []signals.Handler
	// DisableDefaultRevocation turns the default handler off.
	DisableDefaultRevocation bool

	AllowPrivateNetworks bool
	AllowInsecureHTTP    bool
}

type sharedSignals struct {
	tx       *signals.Transmitter
	rx       *signals.Receiver
	emit     bool
	subjects signals.SubjectFunc
	cancel   context.CancelFunc
}

// via marker that keeps received revocations from being re-emitted, which
// would otherwise ping-pong between two peers.
const sharedSignalsVia = "shared_signals"

func (a *TheAuth) setupSharedSignals(cfg *Config) error {
	c := cfg.SharedSignals
	if c == nil {
		return nil
	}
	if a.as == nil || cfg.AuthorizationServer == nil {
		return errors.New("theauth: Config.SharedSignals requires Config.AuthorizationServer (SETs are signed with its keys)")
	}
	if c.Authenticate == nil {
		return errors.New("theauth: Config.SharedSignals.Authenticate is required")
	}
	issuer := c.Issuer
	if issuer == "" {
		issuer = cfg.AuthorizationServer.Issuer
	}
	base := c.BaseURL
	if base == "" {
		base = issuer
	}
	asvc := a.as
	signer := signals.SignerFunc(func(payload map[string]any) (string, error) {
		key, sig, err := asvc.SigningKeyFor(context.Background(), jwt.AlgEdDSA)
		if err != nil {
			return "", fmt.Errorf("shared signals: signing key: %w", err)
		}
		return jwt.SignPayloadWith(payload, signals.TypeSET, key.KID, jwt.AlgEdDSA, sig)
	})
	tx, err := signals.NewTransmitter(signals.TransmitterConfig{
		Issuer: issuer, BaseURL: base, JWKSURI: strings.TrimRight(issuer, "/") + "/oauth/jwks",
		Signer: signer, Store: c.Store, Authenticate: c.Authenticate,
		AllowPrivateNetworks: c.AllowPrivateNetworks, AllowInsecureHTTP: c.AllowInsecureHTTP,
		MaxAttempts: c.MaxAttempts, BackoffBase: c.BackoffBase, BackoffMax: c.BackoffMax,
		Logger: slog.Default(),
	})
	if err != nil {
		return err
	}
	ss := &sharedSignals{tx: tx, emit: c.EmitFromAudit, subjects: c.SubjectFor}
	if ss.subjects == nil {
		ss.subjects = signals.IssSubSubjects(issuer)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ss.cancel = cancel
	go tx.Start(ctx)

	if r := c.Receiver; r != nil {
		handlers := make([]signals.Handler, 0, len(r.Handlers)+1)
		if !r.DisableDefaultRevocation {
			handlers = append(handlers, signals.SessionRevocationHandler(signals.SessionRevocationConfig{
				ResolveUser: func(ctx context.Context, sub signals.Subject) (string, bool, error) {
					id, ok, err := a.resolveSignalUser(ctx, r, sub)
					return id.String(), ok, err
				},
				RevokeSessions: func(ctx context.Context, userID string) error {
					id, err := oklogulid.ParseStrict(userID)
					if err != nil {
						return err
					}
					if err := a.storage.RevokeUserSessions(ctx, id); err != nil {
						return err
					}
					a.EmitAudit(ctx, "session.revoked", TargetRef{Type: "user", ID: userID},
						map[string]any{"scope": "all", "via": sharedSignalsVia})
					return nil
				},
			}))
		}
		handlers = append(handlers, r.Handlers...)
		rx, err := signals.NewReceiver(signals.ReceiverConfig{
			Audience: r.Audience, Issuers: r.Issuers, Authenticate: r.Authenticate, Handlers: handlers,
			AllowPrivateNetworks: r.AllowPrivateNetworks, AllowInsecureHTTP: r.AllowInsecureHTTP,
		})
		if err != nil {
			cancel()
			return err
		}
		ss.rx = rx
	}
	a.signalsSvc = ss
	return nil
}

func (a *TheAuth) resolveSignalUser(ctx context.Context, r *SharedSignalsReceiverConfig, sub signals.Subject) (ULID, bool, error) {
	if r.ResolveUser != nil {
		return r.ResolveUser(ctx, sub)
	}
	if sub.Format != signals.FormatEmail {
		return ULID{}, false, nil
	}
	u, err := a.storage.UserByEmail(ctx, strings.ToLower(sub.Email))
	if err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			return ULID{}, false, nil
		}
		return ULID{}, false, err
	}
	return u.ID, true, nil
}

// SharedSignalsHandler returns the SSF transmitter routes
// (/.well-known/ssf-configuration and /ssf/*), or nil when
// Config.SharedSignals is unset. Mount it at the issuer origin root.
func (a *TheAuth) SharedSignalsHandler() http.Handler {
	if a.signalsSvc == nil {
		return nil
	}
	return a.signalsSvc.tx.Handler()
}

// SharedSignalsTransmitter exposes the transmitter for host code that wants
// to emit custom events (device-compliance-change, assurance-level-change,
// credential-compromise, token-claims-change) with Emit. Nil when off.
func (a *TheAuth) SharedSignalsTransmitter() *signals.Transmitter {
	if a.signalsSvc == nil {
		return nil
	}
	return a.signalsSvc.tx
}

// SharedSignalsReceiverHandler returns the RFC 8935 push endpoint of the
// receiver, or nil when no receiver is configured.
func (a *TheAuth) SharedSignalsReceiverHandler() http.Handler {
	if a.signalsSvc == nil || a.signalsSvc.rx == nil {
		return nil
	}
	return a.signalsSvc.rx
}

// sharedSignalsTap is called from EmitAudit. Emission runs off the request
// goroutine so a slow store never delays a sign-out.
func (a *TheAuth) sharedSignalsTap(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	ss := a.signalsSvc
	if ss == nil || !ss.emit {
		return
	}
	if v, _ := metadata["via"].(string); v == sharedSignalsVia {
		return
	}
	actor := ""
	if u, ok := UserFromContext(ctx); ok && u != nil {
		actor = u.ID.String()
	}
	events := signals.EventsFromAudit(ctx, ss.subjects, action, target.Type, target.ID, metadata, actor, time.Now())
	if len(events) == 0 {
		return
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ss.tx.Emit(bg, events...); err != nil {
			slog.Warn("theauth: shared signals emit failed", "action", action, "error", err)
		}
	}()
}

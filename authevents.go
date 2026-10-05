package theauth

import (
	"context"
	"net/http"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/authevents"
)

// AuthEventType names one security-relevant authentication event.
type AuthEventType = authevents.Type

// The AuthEventType values emitted by the library. The strings are stable.
const (
	AuthEventLoginSuccess           = authevents.LoginSuccess
	AuthEventLoginFailure           = authevents.LoginFailure
	AuthEventMFASuccess             = authevents.MFASuccess
	AuthEventMFAFailure             = authevents.MFAFailure
	AuthEventPasswordChanged        = authevents.PasswordChanged
	AuthEventPasswordResetRequested = authevents.PasswordResetRequested
	AuthEventPasswordResetCompleted = authevents.PasswordResetCompleted
	AuthEventPasskeyAdded           = authevents.PasskeyAdded
	AuthEventPasskeyRemoved         = authevents.PasskeyRemoved
	AuthEventPasskeyRenamed         = authevents.PasskeyRenamed
	AuthEventPasskeyCloneWarning    = authevents.PasskeyCloneWarning
	AuthEventTOTPEnrolled           = authevents.TOTPEnrolled
	AuthEventTOTPDisabled           = authevents.TOTPDisabled
	AuthEventRecoveryCodesRegen     = authevents.RecoveryCodesRegen
	AuthEventSessionRevoked         = authevents.SessionRevoked
	AuthEventTokenMinted            = authevents.TokenMinted
	AuthEventTokenRevoked           = authevents.TokenRevoked
	AuthEventOAuthLinked            = authevents.OAuthLinked
)

// AuthEvent is the PII-minimal record handed to Config.AuthEventSink. It
// carries a user id and a truncated IP prefix, never an email, name or token.
type AuthEvent = authevents.Event

// AuthEventSink receives every AuthEvent synchronously on the emitting
// goroutine. Implementations must return quickly and must not block; a
// panic is recovered and logged.
type AuthEventSink = authevents.Sink

// AuthEventChannelSink returns an AuthEventSink that forwards events to ch
// without ever blocking: when ch is full the event is dropped.
func AuthEventChannelSink(ch chan<- AuthEvent) AuthEventSink { return authevents.ChannelSink(ch) }

// RecordTokenMinted is the hook point for token issuers (API tokens, device
// codes, service tokens) to report a mint. kind is a short label such as
// "api" or "device"; it must not contain the token itself.
func (a *TheAuth) RecordTokenMinted(ctx context.Context, userID ULID, kind string) {
	a.EmitAudit(ctx, "token.minted", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"kind": kind})
}

// RecordTokenRevoked is the revoke counterpart of RecordTokenMinted.
func (a *TheAuth) RecordTokenRevoked(ctx context.Context, userID ULID, kind string) {
	a.EmitAudit(ctx, "token.revoked", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"kind": kind})
}

func (a *TheAuth) dispatchAuthEvent(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	if a.authEventSink == nil {
		return
	}
	md, hasMD := audit.MetadataFromContext(ctx)
	ctxUser := ""
	if u, ok := UserFromContext(ctx); ok && u != nil {
		ctxUser = u.ID.String()
	}
	if ev, ok := authevents.Build(action, target.Type, target.ID, metadata, md, hasMD, ctxUser); ok {
		authevents.Deliver(ctx, a.authEventSink, ev)
	}
}

// auditContextMiddleware attaches the client IP and user agent to the
// request context so every audit event and AuthEvent carries them.
func (a *TheAuth) auditContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := audit.MetadataFromContext(r.Context()); !ok {
			ctx := audit.WithAuditMetadata(r.Context(), audit.AuditMetadata{
				IP:        extractClientIPTrusting(r, a.trustedProxies),
				UserAgent: r.UserAgent(),
			})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

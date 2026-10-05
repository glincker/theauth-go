package theauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/audit"
)

// AuthEventType names one security-relevant authentication event.
type AuthEventType string

// The AuthEventType values emitted by the library. The strings are stable.
const (
	AuthEventLoginSuccess           AuthEventType = "login.success"
	AuthEventLoginFailure           AuthEventType = "login.failure"
	AuthEventMFASuccess             AuthEventType = "mfa.success"
	AuthEventMFAFailure             AuthEventType = "mfa.failure"
	AuthEventPasswordChanged        AuthEventType = "password.changed"
	AuthEventPasswordResetRequested AuthEventType = "password.reset_requested"
	AuthEventPasswordResetCompleted AuthEventType = "password.reset_completed"
	AuthEventPasskeyAdded           AuthEventType = "passkey.added"
	AuthEventPasskeyRemoved         AuthEventType = "passkey.removed"
	AuthEventPasskeyRenamed         AuthEventType = "passkey.renamed"
	AuthEventPasskeyCloneWarning    AuthEventType = "passkey.clone_warning"
	AuthEventTOTPEnrolled           AuthEventType = "totp.enrolled"
	AuthEventTOTPDisabled           AuthEventType = "totp.disabled"
	AuthEventRecoveryCodesRegen     AuthEventType = "totp.recovery_codes_regenerated"
	AuthEventSessionRevoked         AuthEventType = "session.revoked"
	AuthEventTokenMinted            AuthEventType = "token.minted"
	AuthEventTokenRevoked           AuthEventType = "token.revoked"
	AuthEventOAuthLinked            AuthEventType = "oauth.linked"
)

// AuthEvent is the PII-minimal record handed to Config.AuthEventSink. It
// carries a user id and a truncated IP prefix, never an email, name or token.
type AuthEvent struct {
	Type AuthEventType
	At   time.Time
	// UserID is the ULID of the affected user, empty when unknown (for
	// example a failed login for an unregistered address).
	UserID string
	// IPPrefix is the client address masked to /24 (IPv4) or /48 (IPv6).
	IPPrefix string
	// Method is the credential kind involved, such as "password", "totp",
	// "passkey" or "oauth:github". May be empty.
	Method string
	// Reason is a short machine-readable cause on failures. May be empty.
	Reason string
}

// AuthEventSink receives every AuthEvent synchronously on the emitting
// goroutine. Implementations must return quickly and must not block; a
// panic is recovered and logged.
type AuthEventSink func(ctx context.Context, e AuthEvent)

// AuthEventChannelSink returns an AuthEventSink that forwards events to ch
// without ever blocking: when ch is full the event is dropped.
func AuthEventChannelSink(ch chan<- AuthEvent) AuthEventSink {
	return func(_ context.Context, e AuthEvent) {
		select {
		case ch <- e:
		default:
		}
	}
}

var auditActionToAuthEvent = map[string]AuthEventType{
	"user.login":                AuthEventLoginSuccess,
	"login.failed":              AuthEventLoginFailure,
	"mfa.verified":              AuthEventMFASuccess,
	"mfa.failed":                AuthEventMFAFailure,
	"password.changed":          AuthEventPasswordChanged,
	"password.reset.requested":  AuthEventPasswordResetRequested,
	"password.reset.completed":  AuthEventPasswordResetCompleted,
	"passkey.registered":        AuthEventPasskeyAdded,
	"passkey.deleted":           AuthEventPasskeyRemoved,
	"passkey.renamed":           AuthEventPasskeyRenamed,
	"passkey.clone_warning":     AuthEventPasskeyCloneWarning,
	"totp.enrolled":             AuthEventTOTPEnrolled,
	"totp.disabled":             AuthEventTOTPDisabled,
	"totp.recovery_regenerated": AuthEventRecoveryCodesRegen,
	"session.revoked":           AuthEventSessionRevoked,
	"user.logout":               AuthEventSessionRevoked,
	"token.minted":              AuthEventTokenMinted,
	"token.revoked":             AuthEventTokenRevoked,
	"oauth_account.linked":      AuthEventOAuthLinked,
}

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
	typ, ok := auditActionToAuthEvent[action]
	if !ok {
		return
	}
	ev := AuthEvent{Type: typ, At: time.Now().UTC()}
	if target.Type == "user" {
		ev.UserID = target.ID
	}
	if ev.UserID == "" {
		if v, ok := metadata["user_id"].(string); ok {
			ev.UserID = v
		}
	}
	md, hasMD := audit.MetadataFromContext(ctx)
	if ev.UserID == "" && hasMD && md.ActorUserID != nil {
		ev.UserID = md.ActorUserID.String()
	}
	if ev.UserID == "" {
		if u, ok := UserFromContext(ctx); ok && u != nil {
			ev.UserID = u.ID.String()
		}
	}
	if hasMD {
		ev.IPPrefix = ipPrefix(md.IP)
	}
	if v, ok := metadata["auth_method"].(string); ok {
		ev.Method = v
	} else if v, ok := metadata["method"].(string); ok {
		ev.Method = v
	}
	if v, ok := metadata["reason"].(string); ok {
		ev.Reason = v
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("theauth: AuthEventSink panicked", "panic", r)
		}
	}()
	a.authEventSink(ctx, ev)
}

func ipPrefix(raw string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
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

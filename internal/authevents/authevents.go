// Package authevents defines the PII-minimal authentication event stream.
package authevents

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
)

// Type names one security-relevant authentication event.
type Type string

// The Type values emitted by the library. The strings are stable.
const (
	LoginSuccess           Type = "login.success"
	LoginFailure           Type = "login.failure"
	MFASuccess             Type = "mfa.success"
	MFAFailure             Type = "mfa.failure"
	PasswordChanged        Type = "password.changed"
	PasswordResetRequested Type = "password.reset_requested"
	PasswordResetCompleted Type = "password.reset_completed"
	PasskeyAdded           Type = "passkey.added"
	PasskeyRemoved         Type = "passkey.removed"
	PasskeyRenamed         Type = "passkey.renamed"
	PasskeyCloneWarning    Type = "passkey.clone_warning"
	TOTPEnrolled           Type = "totp.enrolled"
	TOTPDisabled           Type = "totp.disabled"
	RecoveryCodesRegen     Type = "totp.recovery_codes_regenerated"
	SessionRevoked         Type = "session.revoked"
	TokenMinted            Type = "token.minted"
	TokenRevoked           Type = "token.revoked"
	OAuthLinked            Type = "oauth.linked"
)

// Event is the PII-minimal record handed to Config.Sink. It
// carries a user id and a truncated IP prefix, never an email, name or token.
type Event struct {
	Type Type
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

// Sink receives every Event synchronously on the emitting
// goroutine. Implementations must return quickly and must not block; a
// panic is recovered and logged.
type Sink func(ctx context.Context, e Event)

// ChannelSink returns a Sink that forwards events to ch
// without ever blocking: when ch is full the event is dropped.
func ChannelSink(ch chan<- Event) Sink {
	return func(_ context.Context, e Event) {
		select {
		case ch <- e:
		default:
		}
	}
}

var actionToType = map[string]Type{
	"user.login":                LoginSuccess,
	"login.failed":              LoginFailure,
	"mfa.verified":              MFASuccess,
	"mfa.failed":                MFAFailure,
	"password.changed":          PasswordChanged,
	"password.reset.requested":  PasswordResetRequested,
	"password.reset.completed":  PasswordResetCompleted,
	"passkey.registered":        PasskeyAdded,
	"passkey.deleted":           PasskeyRemoved,
	"passkey.renamed":           PasskeyRenamed,
	"passkey.clone_warning":     PasskeyCloneWarning,
	"totp.enrolled":             TOTPEnrolled,
	"totp.disabled":             TOTPDisabled,
	"totp.recovery_regenerated": RecoveryCodesRegen,
	"session.revoked":           SessionRevoked,
	"user.logout":               SessionRevoked,
	"token.minted":              TokenMinted,
	"token.revoked":             TokenRevoked,
	"oauth_account.linked":      OAuthLinked,
}

func IPPrefix(raw string) string {
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

// Build maps an audit action to the PII-minimal Event, reporting false for
// actions that are not authentication events. ctxUserID is the signed-in user, if any.
func Build(action, targetType, targetID string, metadata map[string]any, md audit.AuditMetadata, hasMD bool, ctxUserID string) (Event, bool) {
	typ, ok := actionToType[action]
	if !ok {
		return Event{}, false
	}
	ev := Event{Type: typ, At: time.Now().UTC()}
	if targetType == "user" {
		ev.UserID = targetID
	}
	if ev.UserID == "" {
		if v, ok := metadata["user_id"].(string); ok {
			ev.UserID = v
		}
	}
	if ev.UserID == "" && hasMD && md.ActorUserID != nil {
		ev.UserID = md.ActorUserID.String()
	}
	if ev.UserID == "" {
		ev.UserID = ctxUserID
	}
	if hasMD {
		ev.IPPrefix = IPPrefix(md.IP)
	}
	if v, ok := metadata["auth_method"].(string); ok {
		ev.Method = v
	} else if v, ok := metadata["method"].(string); ok {
		ev.Method = v
	}
	if v, ok := metadata["reason"].(string); ok {
		ev.Reason = v
	}
	return ev, true
}

// Deliver calls sink with ev, recovering and logging a panic.
func Deliver(ctx context.Context, sink Sink, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("theauth: AuthEventSink panicked", "panic", r)
		}
	}()
	sink(ctx, ev)
}

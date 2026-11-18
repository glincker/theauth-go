package mqttauth

import (
	"context"
	"log/slog"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
)

// AuditEvent is one broker decision.
type AuditEvent struct {
	Time     time.Time
	Kind     string // "authn" or "authz"
	Allowed  bool
	Method   string // cert, token, jwt for authn, "" for authz
	DeviceID string
	OrgID    string
	ClientID string
	Action   string
	Topic    string
	Reason   string
	// Code is the machine readable outcome (see the Code constants). Empty for a deny that
	// happened before any device or credential was looked at.
	Code       string
	RemoteAddr string
	Cached     bool
}

// AuditSink receives decisions. Denies are always recorded, allows are sampled (see
// Config.AllowSampleRate). Record must not block the request for long.
type AuditSink interface {
	Record(ctx context.Context, e AuditEvent)
}

// AuditFunc adapts a function to AuditSink.
type AuditFunc func(ctx context.Context, e AuditEvent)

// Record implements AuditSink.
func (f AuditFunc) Record(ctx context.Context, e AuditEvent) { f(ctx, e) }

// SlogSink writes decisions as structured log records.
func SlogSink(l *slog.Logger) AuditSink {
	return AuditFunc(func(ctx context.Context, e AuditEvent) {
		level := slog.LevelInfo
		if !e.Allowed {
			level = slog.LevelWarn
		}
		l.LogAttrs(ctx, level, "mqtt "+e.Kind,
			slog.Bool("allowed", e.Allowed), slog.String("method", e.Method), slog.String("device_id", e.DeviceID),
			slog.String("client_id", e.ClientID), slog.String("action", e.Action), slog.String("topic", e.Topic),
			slog.String("reason", e.Reason), slog.String("code", e.Code), slog.String("remote", e.RemoteAddr))
	})
}

// TheAuthSink writes decisions to the theAuth audit log as mqtt.authn.allow, mqtt.authn.deny,
// mqtt.authz.allow and mqtt.authz.deny rows targeting the device. Rows carry no secrets.
func TheAuthSink(a *theauth.TheAuth) AuditSink {
	return AuditFunc(func(ctx context.Context, e AuditEvent) {
		verdict := "deny"
		if e.Allowed {
			verdict = "allow"
		}
		a.EmitAudit(ctx, "mqtt."+e.Kind+"."+verdict, theauth.TargetRef{Type: "device", ID: e.DeviceID}, map[string]any{
			"principalType": "device",
			// Same marker the TypeScript device module writes, so one query finds both.
			"theauthPrincipal": map[string]string{"type": "device", "id": e.DeviceID},
			"code":             e.Code,
			"orgId":            e.OrgID,
			"method":           e.Method,
			"clientId":         e.ClientID,
			"action":           e.Action,
			"topic":            e.Topic,
			"reason":           e.Reason,
			"remote":           e.RemoteAddr,
			"cached":           e.Cached,
		})
	})
}

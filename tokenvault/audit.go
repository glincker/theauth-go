package tokenvault

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/oklog/ulid/v2"
)

// Audit action names.
const (
	ActionTokenIssued       = "vault.token.issued"
	ActionTokenDenied       = "vault.token.denied"
	ActionCredentialStored  = "vault.credential.stored"
	ActionCredentialRefresh = "vault.credential.refreshed"
	ActionReauthRequired    = "vault.credential.reauth_required"
	ActionCredentialRemoved = "vault.credential.removed"
	ActionKeysRewrapped     = "vault.keys.rewrapped"
)

// Event is one audit record. It never carries a token.
type Event struct {
	Action   string
	UserID   string
	AgentID  string
	Provider string
	Scopes   []string
	// Reason is a stable code on denials, empty otherwise.
	Reason string
	At     time.Time
}

// Auditor records events. When it returns an error for ActionTokenIssued the
// vault withholds the token (fail closed).
type Auditor interface {
	Record(ctx context.Context, e Event) error
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(ctx context.Context, e Event) error

// Record implements Auditor.
func (f AuditorFunc) Record(ctx context.Context, e Event) error { return f(ctx, e) }

// AuditStorageSink writes events to a theauth.AuditStorage as AuditEvents with
// the user as subject and the agent as actor.
type AuditStorageSink struct{ Store theauth.AuditStorage }

// Record implements Auditor.
func (s AuditStorageSink) Record(ctx context.Context, e Event) error {
	md := map[string]any{"provider": e.Provider}
	if len(e.Scopes) > 0 {
		md["scopes"] = e.Scopes
	}
	if e.Reason != "" {
		md["reason"] = e.Reason
	}
	return s.Store.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID:         ulid.Make(),
		Action:     e.Action,
		TargetType: "vault_credential",
		TargetID:   e.Provider,
		SubjectID:  e.UserID,
		ActorID:    e.AgentID,
		Metadata:   md,
		CreatedAt:  e.At,
	}})
}

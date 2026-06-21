package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/audit"
)

// Audit forwarders. PR D architecture reorg (2026-06-20) moved the
// goroutine-backed audit writer to internal/audit (Service alongside the
// existing Emitter interface); the public EmitAudit / QueryAudit / Stats
// entry points kept their exact signatures so callers in this package and
// downstream consumers continue to compile unchanged.
//
// The context-extraction logic (UserFromContext, SessionFromContext) lives
// here because the context keys live in root. The root forwarder pulls
// the actor + session bundle and hands them to internal/audit's Emit; the
// internal package then merges any WithAuditMetadata override.

// AuditMetadata is the optional bundle a caller may attach to a context to
// override the auto-derived actor / org / IP / UA. Re-exported from
// internal/audit so the v1.0 public surface is unchanged.
type AuditMetadata = audit.AuditMetadata

// WithAuditMetadata attaches an AuditMetadata to ctx; EmitAudit reads it.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return audit.WithAuditMetadata(ctx, md)
}

// EmitAudit enqueues an audit event for asynchronous batched write. Non-
// blocking: when the writer channel is full the event is dropped and
// Stats.AuditDropped increments by 1.
//
// EmitAudit may be called from any goroutine. The metadata map is mutated
// in place by the redactor; callers must not retain references after the
// call (or, equivalently, must defensively copy before passing in).
//
// When Config.Audit is nil EmitAudit is a silent no-op. When Close has
// been called EmitAudit is also a silent no-op.
func (a *TheAuth) EmitAudit(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	if a.auditSvc == nil {
		return
	}
	var actorUser *ULID
	if u, ok := UserFromContext(ctx); ok && u != nil {
		id := u.ID
		actorUser = &id
	}
	var actorSession *Session
	if s, ok := SessionFromContext(ctx); ok && s != nil {
		actorSession = s
	}
	a.auditSvc.Emit(ctx, action, target, metadata, actorUser, actorSession)
}

// QueryAudit returns up to q.Limit events plus an opaque cursor for the
// next page. Caller is responsible for permission-checking; this method
// does no auth.
func (a *TheAuth) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, string, error) {
	if a.auditSvc == nil {
		return a.storage.QueryAuditEvents(ctx, q)
	}
	return a.auditSvc.Query(ctx, q)
}

// Package audit defines the audit-emission interface that internal service
// packages depend on. Phase A of the architecture reorg (2026-06) introduced
// this seam so service packages (session, magiclink, organizations, rbac,
// scim) can record audit events without importing the root theauth package
// (which would create a cycle: root imports internal/X for the constructor,
// internal/X would have to import root for EmitAudit).
//
// The root *theauth.TheAuth satisfies Emitter naturally because its
// EmitAudit method already has this exact signature. Each internal service
// is constructed with an Emitter, and tests can inject a no-op or recording
// emitter without spinning up a full TheAuth.
package audit

import (
	"context"

	"github.com/glincker/theauth-go/internal/models"
)

// Emitter is the audit-emission seam shared by every internal service
// package. The shape mirrors the existing EmitAudit method on *TheAuth so
// the root type satisfies the interface without a wrapper.
//
// Implementations MUST NOT block the caller: the canonical implementation
// enqueues onto a buffered channel and drops on overflow. Implementations
// MUST be safe to call from any goroutine.
type Emitter interface {
	EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any)
}

// NoopEmitter is an Emitter that discards every event. Useful in tests and
// in code paths that do not configure audit.
type NoopEmitter struct{}

// EmitAudit on NoopEmitter is a silent drop.
func (NoopEmitter) EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any) {
}

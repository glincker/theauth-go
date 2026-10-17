// Package audit defines the Emitter seam that internal service packages depend on. It exists so
// they can record audit events without importing root, which would form a cycle. *theauth.TheAuth
// satisfies Emitter naturally.
package audit

import (
	"context"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Emitter is the audit emission seam shared by the internal service packages. Implementations must
// never block the caller and must be safe from any goroutine.
type Emitter interface {
	EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any)
}

// NoopEmitter is an Emitter that discards every event. Useful in tests and
// in code paths that do not configure audit.
type NoopEmitter struct{}

// EmitAudit on NoopEmitter is a silent drop.
func (NoopEmitter) EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any) {
}

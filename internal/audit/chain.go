package audit

import (
	"context"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// ChainVerifier is implemented by backends that keep a tamper-evident audit hash chain (sqlite,
// postgres, mysql).
type ChainVerifier interface {
	ChainSupported() bool
	VerifyAuditChain(ctx context.Context) (models.AuditChainResult, error)
}

// VerifyChain verifies the chain held by st. A backend without a chain gets Supported and OK both false with
// ErrAuditChainUnsupported, so an unchecked log is never reported as verified.
func VerifyChain(ctx context.Context, st Storage) (models.AuditChainResult, error) {
	if v, ok := st.(ChainVerifier); ok && v.ChainSupported() {
		return v.VerifyAuditChain(ctx)
	}
	return models.AuditChainResult{Supported: false, OK: false}, models.ErrAuditChainUnsupported
}

// VerifyChain verifies the audit chain of the service's storage backend. See
// the package-level VerifyChain.
func (s *Service) VerifyChain(ctx context.Context) (models.AuditChainResult, error) {
	return VerifyChain(ctx, s.storage)
}

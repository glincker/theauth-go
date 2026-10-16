package audit

import (
	"context"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// ChainVerifier is implemented by storage backends that keep a tamper-evident
// audit hash chain (sqlite, postgres, mysql). Backends without a chain either do
// not implement it or report ChainSupported() == false.
type ChainVerifier interface {
	ChainSupported() bool
	VerifyAuditChain(ctx context.Context) (models.AuditChainResult, error)
}

// VerifyChain verifies the audit hash chain held by st. When the backend has no
// chain it returns an explicit unsupported result (Supported and OK both
// false) together with models.ErrAuditChainUnsupported. It never reports a
// pass for a backend it could not check.
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

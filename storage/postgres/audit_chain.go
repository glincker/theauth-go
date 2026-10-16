package postgres

import (
	"context"

	"github.com/glincker/theauth-go/v2"
)

// ChainSupported reports whether this backend keeps a tamper-evident audit
// hash chain. It does not: accountability fields are stored under the reserved
// "_accountability" metadata key and rows are not hash-linked. Only
// storage/sqlite is tamper-evident today.
func (s *Store) ChainSupported() bool { return false }

// VerifyAuditChain returns an explicit unsupported result, never a pass.
func (s *Store) VerifyAuditChain(_ context.Context) (theauth.AuditChainResult, error) {
	return theauth.AuditChainResult{Supported: false, OK: false}, theauth.ErrAuditChainUnsupported
}

package theauth

import (
	"context"
)

// jwks.go: thin forwarders for the JWKS rotation surface. PR B
// architecture reorg (2026-06-20) moved the JWKS state machine and the
// Ed25519 keypair lifecycle into internal/as. PR G (2026-06-21) removed
// the unexported currentSigningKey / publicKeyByKID helpers because every
// in-tree caller now goes through *as.Service directly (the AS handler
// package, the v2 token services, and the JWT verify middleware all
// import internal/as). Only the operator-facing RotateSigningKey method
// remains on the root receiver because it is part of the v2.0 public API.

// RotateSigningKey advances the JWKS state machine one step: previous
// (if any) is retired, current becomes previous, next becomes current,
// and a fresh next is minted. Idempotent under concurrent callers (each
// call mints one fresh next). Operators can invoke this on emergency
// without waiting for the scheduled tick.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	return a.as.RotateSigningKey(ctx)
}

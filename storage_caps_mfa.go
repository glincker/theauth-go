package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/totp"
)

// WebAuthnRenameStorage is the optional capability behind passkey rename
// (PATCH /auth/webauthn/credentials/{id}). Adapters that do not implement it
// answer 501 on that route; everything else keeps working.
type WebAuthnRenameStorage interface {
	// RenameWebAuthnCredential sets the display name of the credential
	// identified by id when it belongs to userID. Returns ErrStorageNotFound
	// when no such row exists.
	RenameWebAuthnCredential(ctx context.Context, id, userID ULID, name string) error
}

// RecoveryCodeStorage is the optional capability behind GET /auth/totp
// (remaining recovery codes) and POST /auth/totp/recovery-codes. Without it
// the status route reports -1 remaining and regeneration answers 501.
type RecoveryCodeStorage interface {
	// CountUnusedRecoveryCodes returns how many unused codes userID holds.
	CountUnusedRecoveryCodes(ctx context.Context, userID ULID) (int, error)
	// ReplaceRecoveryCodes atomically deletes every code of userID and
	// inserts codes.
	ReplaceRecoveryCodes(ctx context.Context, userID ULID, codes []RecoveryCode) error
}

// TOTPStatus reports whether TOTP is enrolled and how many recovery codes
// remain (-1 when the storage cannot count them).
type TOTPStatus = totp.Status

// TOTPStatus returns the user's TOTP enrollment state.
func (a *TheAuth) TOTPStatus(ctx context.Context, userID ULID) (TOTPStatus, error) {
	return a.totpSvc.Status(ctx, userID)
}

// RegenerateRecoveryCodes replaces the user's recovery codes and returns the
// new plaintext codes once. The user must have TOTP enrolled.
func (a *TheAuth) RegenerateRecoveryCodes(ctx context.Context, userID ULID) ([]string, error) {
	return a.totpSvc.RegenerateRecoveryCodes(ctx, userID)
}

// RenamePasskey changes the display name of one of the user's passkeys.
func (a *TheAuth) RenamePasskey(ctx context.Context, id, userID ULID, name string) error {
	return a.webauthnSvc.RenameCredential(ctx, id, userID, name)
}

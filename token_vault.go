package theauth

import (
	"context"
	"time"
)

// Vault credential states stored in VaultCredential.Status.
const (
	// VaultStatusActive means the credential can be used and refreshed.
	VaultStatusActive = "active"
	// VaultStatusNeedsReauth means the provider rejected the refresh token and
	// the user must connect the provider again.
	VaultStatusNeedsReauth = "needs_reauth"
)

// VaultCredential is one stored third party OAuth credential, keyed by
// (UserID, Provider). AccessCT and RefreshCT are opaque sealed blobs produced
// by the tokenvault package; a store never sees a plaintext token and must not
// try to interpret the bytes.
type VaultCredential struct {
	ID        string
	UserID    string
	Provider  string
	AccountID string
	Scopes    []string
	AccessCT  []byte
	// RefreshCT is empty when the provider issued no refresh token.
	RefreshCT []byte
	// AccessExpiresAt is the zero time when the access token never expires.
	AccessExpiresAt time.Time
	Status          string
	// Version is a counter the store maintains: 1 on first insert, then
	// incremented on every successful write. It backs compare and swap.
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TokenVaultStorage is the optional storage capability behind the tokenvault
// package. It is additive: a store that lacks it only fails when a tokenvault
// is constructed over it.
//
// There is one credential per (UserID, Provider). Implementations must copy
// slices on the way in and out. A missing row is reported as
// storage.ErrNotFound.
type TokenVaultStorage interface {
	// PutVaultCredential inserts or replaces the credential for
	// (c.UserID, c.Provider). It assigns c.ID when empty on first insert, keeps
	// the original ID and CreatedAt on replace, and sets Version to the previous
	// version plus one (1 on insert). It returns the stored row.
	PutVaultCredential(ctx context.Context, c VaultCredential) (VaultCredential, error)
	// VaultCredentialByUserProvider returns the credential or storage.ErrNotFound.
	VaultCredentialByUserProvider(ctx context.Context, userID, provider string) (*VaultCredential, error)
	// SwapVaultCredential replaces the row for (c.UserID, c.Provider) only when
	// its stored Version equals expectedVersion, and then sets Version to
	// expectedVersion+1. It reports false when the version differs or the row is
	// gone. It must be one atomic conditional write.
	SwapVaultCredential(ctx context.Context, c VaultCredential, expectedVersion int64) (bool, error)
	// ListVaultCredentials returns every credential of one user.
	ListVaultCredentials(ctx context.Context, userID string) ([]VaultCredential, error)
	// ScanVaultCredentials returns up to limit credentials whose ID sorts after
	// afterID, in ascending ID order. Used for key rotation sweeps.
	ScanVaultCredentials(ctx context.Context, afterID string, limit int) ([]VaultCredential, error)
	// DeleteVaultCredential removes the credential. Deleting a missing row is not an error.
	DeleteVaultCredential(ctx context.Context, userID, provider string) error
}

package theauth

import (
	"context"
	"time"
)

const (
	// VaultStatusActive means the credential can be used and refreshed.
	VaultStatusActive = "active"
	// VaultStatusNeedsReauth means the provider rejected the refresh token; the user must connect again.
	VaultStatusNeedsReauth = "needs_reauth"
)

// VaultCredential is one stored third party OAuth credential, keyed by (UserID, Provider). AccessCT
// and RefreshCT are sealed by the tokenvault package; a store never sees a plaintext token.
type VaultCredential struct {
	ID              string
	UserID          string
	Provider        string
	AccountID       string
	Scopes          []string
	AccessCT        []byte
	RefreshCT       []byte
	AccessExpiresAt time.Time
	Status          string
	// Version is maintained by the store: 1 on first insert, then incremented on each write. It backs
	// compare and swap.
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TokenVaultStorage is the optional storage capability behind the tokenvault package.
// Implementations copy slices on the way in and out, and report a missing row as
// storage.ErrNotFound. There is one credential per (UserID, Provider).
type TokenVaultStorage interface {
	// PutVaultCredential inserts or replaces the credential for (UserID, Provider). Replacement keeps
	// the ID and CreatedAt and bumps Version.
	PutVaultCredential(ctx context.Context, c VaultCredential) (VaultCredential, error)
	VaultCredentialByUserProvider(ctx context.Context, userID, provider string) (*VaultCredential, error)
	// SwapVaultCredential replaces the row only when its stored Version equals expectedVersion. It
	// must be one atomic conditional write and reports false on a version mismatch or a missing row.
	SwapVaultCredential(ctx context.Context, c VaultCredential, expectedVersion int64) (bool, error)
	ListVaultCredentials(ctx context.Context, userID string) ([]VaultCredential, error)
	// ScanVaultCredentials pages through credentials in ID order, for key rotation sweeps.
	ScanVaultCredentials(ctx context.Context, afterID string, limit int) ([]VaultCredential, error)
	DeleteVaultCredential(ctx context.Context, userID, provider string) error
}

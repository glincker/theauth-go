package theauth

import (
	"context"

	"github.com/glincker/theauth-go/v2/internal/importer"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// ErrImportDuplicate is returned by the Import helpers when the record already exists; callers may treat it as already imported.
var ErrImportDuplicate = models.ErrImportDuplicate

// ErrImportInvalid wraps every Import helper validation failure.
var ErrImportInvalid = importer.ErrImportInvalid

// ImportUserStorage is the storage surface ImportUserTo needs.
type ImportUserStorage interface {
	UserStorage
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
}

// ImportedUser is an existing account to insert. PasswordHash is stored verbatim and may be empty.
type ImportedUser = importer.ImportedUser

// ImportedTOTP is an existing, already-enrolled TOTP secret.
type ImportedTOTP = importer.ImportedTOTP

// ImportedWebAuthnCredential is an existing passkey or security key.
type ImportedWebAuthnCredential = importer.ImportedWebAuthnCredential

// ImportUserTo inserts an existing user and its password hash into store, with no TheAuth instance.
func ImportUserTo(ctx context.Context, store ImportUserStorage, in ImportedUser) (User, error) {
	if store == nil {
		return User{}, importer.ErrNilStorage
	}
	return importer.ImportUserTo(ctx, store, in)
}

// ImportTOTPSecretTo encrypts the plaintext secret with encryptionKey and stores it as confirmed, with no TheAuth instance.
func ImportTOTPSecretTo(ctx context.Context, store TOTPStorage, encryptionKey []byte, in ImportedTOTP) error {
	if store == nil {
		return importer.ErrNilStorage
	}
	return importer.ImportTOTPSecretTo(ctx, store, encryptionKey, in)
}

// ImportWebAuthnCredentialTo inserts an existing credential into store, with no TheAuth instance.
func ImportWebAuthnCredentialTo(ctx context.Context, store WebAuthnStorage, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	if store == nil {
		return WebAuthnCredential{}, importer.ErrNilStorage
	}
	return importer.ImportWebAuthnCredentialTo(ctx, store, in)
}

// ImportUser inserts an existing user through the configured storage; see ImportUserTo.
func (a *TheAuth) ImportUser(ctx context.Context, in ImportedUser) (User, error) {
	return ImportUserTo(ctx, a.storage, in)
}

// ImportTOTPSecret encrypts a plaintext secret with Config.EncryptionKey and stores it as confirmed; see ImportTOTPSecretTo.
func (a *TheAuth) ImportTOTPSecret(ctx context.Context, in ImportedTOTP) error {
	return ImportTOTPSecretTo(ctx, a.storage, a.encryptionKey, in)
}

// ImportWebAuthnCredential inserts an existing credential through the configured storage; see ImportWebAuthnCredentialTo.
func (a *TheAuth) ImportWebAuthnCredential(ctx context.Context, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	return ImportWebAuthnCredentialTo(ctx, a.storage, in)
}

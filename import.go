package theauth

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// ErrImportDuplicate is returned by the Import helpers when the record already exists; callers may treat it as already imported.
var ErrImportDuplicate = errors.New("theauth: import: record already exists")

// ErrImportInvalid wraps every Import helper validation failure.
var ErrImportInvalid = errors.New("theauth: import: invalid record")

func importInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrImportInvalid, fmt.Sprintf(format, args...))
}

// ImportUserStorage is the storage surface ImportUserTo needs.
type ImportUserStorage interface {
	UserStorage
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
}

// ImportedUser is an existing account to insert. PasswordHash is stored verbatim and may be empty.
type ImportedUser struct {
	// ID is optional; a new one is generated when zero.
	ID              ULID
	Email           string
	EmailVerifiedAt *time.Time
	Name            string
	AvatarURL       string
	// PasswordHash is an Argon2id PHC string, or a bcrypt hash when Config.PasswordPolicy.AllowLegacyBcrypt is set.
	PasswordHash string
	CreatedAt    time.Time
}

// ImportUserTo inserts an existing user and its password hash into store, with no TheAuth instance.
func ImportUserTo(ctx context.Context, store ImportUserStorage, in ImportedUser) (User, error) {
	if store == nil {
		return User{}, errors.New("theauth: nil storage")
	}
	email := strings.TrimSpace(in.Email)
	if email == "" || len(email) > 320 || !strings.Contains(email, "@") {
		return User{}, importInvalid("user email")
	}
	if _, err := store.UserByEmail(ctx, email); err == nil {
		return User{}, fmt.Errorf("theauth: import user: %w", ErrImportDuplicate)
	} else if !errors.Is(err, ErrStorageNotFound) {
		return User{}, fmt.Errorf("theauth: import user: look up email: %w", err)
	}
	id := in.ID
	if id == (ULID{}) {
		id = ulid.New()
	}
	created := in.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	u, err := store.CreateUser(ctx, User{
		ID: id, Email: email, EmailVerifiedAt: in.EmailVerifiedAt, Name: in.Name, AvatarURL: in.AvatarURL,
		CreatedAt: created.UTC(), UpdatedAt: created.UTC(),
	})
	if err != nil {
		return User{}, fmt.Errorf("theauth: import user: %w", err)
	}
	if in.PasswordHash != "" {
		if err := store.SetUserPassword(ctx, u.ID, in.PasswordHash); err != nil {
			return User{}, fmt.Errorf("theauth: import user: set password hash: %w", err)
		}
	}
	return u, nil
}

// ImportedTOTP is an existing, already-enrolled TOTP secret.
//
// Recovery codes are deliberately not importable: their hashes are salted by
// this library, so affected users must regenerate them after the import.
type ImportedTOTP struct {
	UserID ULID
	// Secret is the plaintext base32 shared secret exactly as the authenticator app holds it.
	Secret      string
	ConfirmedAt time.Time
	CreatedAt   time.Time
}

// ImportTOTPSecretTo encrypts the plaintext secret with encryptionKey and stores it as confirmed, with no TheAuth instance.
func ImportTOTPSecretTo(ctx context.Context, store TOTPStorage, encryptionKey []byte, in ImportedTOTP) error {
	if store == nil {
		return errors.New("theauth: nil storage")
	}
	if in.UserID == (ULID{}) {
		return importInvalid("totp user id")
	}
	secret := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(in.Secret))
	if secret == "" {
		return importInvalid("totp secret is empty")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return importInvalid("totp secret is not base32")
	}
	if _, err := store.TOTPSecretByUserID(ctx, in.UserID); err == nil {
		return fmt.Errorf("theauth: import totp secret: %w", ErrImportDuplicate)
	} else if !errors.Is(err, ErrStorageNotFound) {
		return fmt.Errorf("theauth: import totp secret: look up user: %w", err)
	}
	enc, err := crypto.Encrypt(encryptionKey, []byte(secret))
	if err != nil {
		return fmt.Errorf("theauth: import totp secret: encrypt: %w", err)
	}
	now := time.Now().UTC()
	created, confirmed := in.CreatedAt, in.ConfirmedAt
	if created.IsZero() {
		created = now
	}
	if confirmed.IsZero() {
		confirmed = now
	}
	if err := store.UpsertPendingTOTPSecret(ctx, TOTPSecret{
		UserID: in.UserID, SecretEnc: enc, CreatedAt: created.UTC(), UpdatedAt: created.UTC(),
	}); err != nil {
		return fmt.Errorf("theauth: import totp secret: %w", err)
	}
	if err := store.ConfirmTOTPSecret(ctx, in.UserID, confirmed.UTC()); err != nil {
		return fmt.Errorf("theauth: import totp secret: confirm: %w", err)
	}
	return nil
}

// ImportedWebAuthnCredential is an existing passkey or security key. The attestation type is not persisted by this library, so it is not accepted.
type ImportedWebAuthnCredential struct {
	// ID is optional; a new one is generated when zero.
	ID     ULID
	UserID ULID
	// CredentialID is the raw authenticator credential ID, and PublicKey the COSE-encoded key.
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	AAGUID         []byte
	Name           string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	BackupEligible *bool
	BackupState    *bool
}

// ImportWebAuthnCredentialTo inserts an existing credential into store, with no TheAuth instance.
func ImportWebAuthnCredentialTo(ctx context.Context, store WebAuthnStorage, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	if store == nil {
		return WebAuthnCredential{}, errors.New("theauth: nil storage")
	}
	if in.UserID == (ULID{}) {
		return WebAuthnCredential{}, importInvalid("webauthn user id")
	}
	if len(in.CredentialID) == 0 || len(in.CredentialID) > 1024 {
		return WebAuthnCredential{}, importInvalid("webauthn credential id length")
	}
	if len(in.PublicKey) == 0 {
		return WebAuthnCredential{}, importInvalid("webauthn public key is empty")
	}
	if len(in.AAGUID) != 0 && len(in.AAGUID) != 16 {
		return WebAuthnCredential{}, importInvalid("webauthn aaguid must be 16 bytes")
	}
	if _, err := store.WebAuthnCredentialByCredentialID(ctx, in.CredentialID); err == nil {
		return WebAuthnCredential{}, fmt.Errorf("theauth: import webauthn credential: %w", ErrImportDuplicate)
	} else if !errors.Is(err, ErrStorageNotFound) {
		return WebAuthnCredential{}, fmt.Errorf("theauth: import webauthn credential: look up: %w", err)
	}
	id := in.ID
	if id == (ULID{}) {
		id = ulid.New()
	}
	created := in.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	saved, err := store.InsertWebAuthnCredential(ctx, WebAuthnCredential{
		ID: id, UserID: in.UserID, CredentialID: slices.Clone(in.CredentialID), PublicKey: slices.Clone(in.PublicKey),
		SignCount: in.SignCount, Transports: slices.Clone(in.Transports), AAGUID: slices.Clone(in.AAGUID),
		Name: in.Name, CreatedAt: created.UTC(), LastUsedAt: in.LastUsedAt,
		BackupEligible: in.BackupEligible, BackupState: in.BackupState,
	})
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("theauth: import webauthn credential: %w", err)
	}
	return saved, nil
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

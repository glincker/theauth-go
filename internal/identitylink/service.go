// Package identitylink owns the identity-linking methods: link an OAuth account, link a password,
// merge accounts and unlink a provider. Every method requires a full session and emits audit
// events. The package declares its own Storage and SessionStore interfaces, so root wires the
// adapters in without an import cycle.
package identitylink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Storage is the minimal persistence subset this package needs.
type Storage interface {
	// Session lookup.
	SessionByTokenHash(ctx context.Context, hash []byte) (*models.Session, error)

	// OAuth accounts.
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error)
	OAuthAccountsByUserID(ctx context.Context, userID models.ULID) ([]models.OAuthAccount, error)
	UpsertOAuthAccount(ctx context.Context, a models.OAuthAccount) (models.OAuthAccount, error)
	MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID models.ULID) error
	DeleteOAuthAccountByProvider(ctx context.Context, userID models.ULID, provider string) error

	// Passwords.
	SetUserPassword(ctx context.Context, userID models.ULID, passwordHash string) error
	UserPasswordHashByID(ctx context.Context, userID models.ULID) (string, error)
	MovePasswordHash(ctx context.Context, primaryID, secondaryID models.ULID) error

	// WebAuthn.
	WebAuthnCredentialsByUserID(ctx context.Context, userID models.ULID) ([]models.WebAuthnCredential, error)
	MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID models.ULID) error

	// TOTP.
	TOTPSecretByUserID(ctx context.Context, userID models.ULID) (*models.TOTPSecret, error)
	MoveTOTPSecret(ctx context.Context, primaryID, secondaryID models.ULID) error

	// Sessions.
	RevokeUserSessions(ctx context.Context, userID models.ULID) error

	// Users.
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
}

// Service owns the identity-linking and account-merge operations.
type Service struct {
	storage Storage
	encKey  []byte
	auditEm audit.Emitter
}

// New constructs a Service. encKey is the same 32-byte AES key used by the
// root for token encryption; auditEm receives structured audit events.
func New(storage Storage, encKey []byte, em audit.Emitter) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{storage: storage, encKey: encKey, auditEm: em}
}

// requireFullSession resolves sessionToken and requires AuthLevel full. It returns
// ErrStepUpRequired for a pending or missing session.
func (s *Service) requireFullSession(ctx context.Context, sessionToken string) (*models.Session, error) {
	hash := crypto.HashToken(sessionToken)
	sess, err := s.storage.SessionByTokenHash(ctx, hash)
	if err != nil {
		return nil, models.ErrStepUpRequired
	}
	if sess == nil || sess.RevokedAt != nil {
		return nil, models.ErrStepUpRequired
	}
	if sess.AuthLevel != "" && sess.AuthLevel != models.AuthLevelFull {
		return nil, models.ErrStepUpRequired
	}
	return sess, nil
}

// authMethodCount counts the authentication methods bound to the user: the password, each OAuth
// provider, each passkey, and TOTP.
func (s *Service) authMethodCount(ctx context.Context, userID models.ULID) (int, error) {
	count := 0

	hash, err := s.storage.UserPasswordHashByID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("identitylink: count auth methods (password): %w", err)
	}
	if hash != "" {
		count++
	}

	oauths, err := s.storage.OAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("identitylink: count auth methods (oauth): %w", err)
	}
	count += len(oauths)

	creds, err := s.storage.WebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("identitylink: count auth methods (webauthn): %w", err)
	}
	count += len(creds)

	totp, err := s.storage.TOTPSecretByUserID(ctx, userID)
	if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
		return 0, fmt.Errorf("identitylink: count auth methods (totp): %w", err)
	}
	if totp != nil && totp.ConfirmedAt != nil {
		count++
	}

	return count, nil
}

// LinkOAuthToCurrentUser binds an already-exchanged OAuth account to the authenticated user. The
// caller runs the OAuth code flow and passes the provider user ID. If the account belongs to
// another user it returns *IdentityConflictError, and a pending session gets ErrStepUpRequired.
func (s *Service) LinkOAuthToCurrentUser(
	ctx context.Context,
	sessionToken, providerName, providerUserID string,
	accessTokenEnc, refreshTokenEnc []byte,
	expiresAt *time.Time,
	scope string,
) error {
	sess, err := s.requireFullSession(ctx, sessionToken)
	if err != nil {
		return err
	}

	// Check whether the OAuth account already exists.
	existing, err := s.storage.OAuthAccountByProviderUserID(ctx, providerName, providerUserID)
	if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
		return fmt.Errorf("identitylink: lookup oauth account: %w", err)
	}

	if existing != nil {
		if existing.UserID == sess.UserID {
			// Already linked to this user; idempotent success.
			return nil
		}
		// Linked to a different user: surface conflict.
		return &models.IdentityConflictError{ConflictingUserID: existing.UserID}
	}

	// Insert / update the OAuth account row bound to the current user.
	now := time.Now()
	_, err = s.storage.UpsertOAuthAccount(ctx, models.OAuthAccount{
		ID:              ulid.New(),
		UserID:          sess.UserID,
		Provider:        providerName,
		ProviderUserID:  providerUserID,
		AccessTokenEnc:  accessTokenEnc,
		RefreshTokenEnc: refreshTokenEnc,
		ExpiresAt:       expiresAt,
		Scope:           scope,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		return fmt.Errorf("identitylink: upsert oauth account: %w", err)
	}

	s.auditEm.EmitAudit(ctx, "identity.linked", models.TargetRef{Type: "user", ID: sess.UserID.String()}, map[string]any{
		"provider": providerName,
		"method":   "oauth",
	})
	return nil
}

// LinkPasswordToCurrentUser adds email and password as a backup method for the authenticated user.
// The password is hashed with the same Argon2id parameters as password.Service. A pending session
// gets ErrStepUpRequired.
func (s *Service) LinkPasswordToCurrentUser(ctx context.Context, sessionToken, password string) error {
	sess, err := s.requireFullSession(ctx, sessionToken)
	if err != nil {
		return err
	}

	if len(password) < 12 {
		return models.NewError(models.CodeWeakPassword, "password must be at least 12 characters", nil)
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("identitylink: hash password: %w", err)
	}

	if err := s.storage.SetUserPassword(ctx, sess.UserID, hash); err != nil {
		return fmt.Errorf("identitylink: set user password: %w", err)
	}
	s.auditEm.EmitAudit(ctx, "password.changed", models.TargetRef{Type: "user", ID: sess.UserID.String()}, nil)

	s.auditEm.EmitAudit(ctx, "identity.linked", models.TargetRef{Type: "user", ID: sess.UserID.String()}, map[string]any{
		"method": "password",
	})
	return nil
}

// MergeInput carries caller-supplied merge options.
type MergeInput struct {
	// AuditReason is an optional free-text reason for the merge, written to
	// the audit event metadata.
	AuditReason string
}

// MergeAccounts moves every authentication method from secondaryID to primaryID and revokes the
// secondary user's sessions. primaryID must be the authenticated user and the two IDs must differ.
// Not transactional, but a retry is safe because each move no-ops once done.
func (s *Service) MergeAccounts(
	ctx context.Context,
	sessionToken string,
	secondaryID models.ULID,
	input MergeInput,
) error {
	sess, err := s.requireFullSession(ctx, sessionToken)
	if err != nil {
		return err
	}
	primaryID := sess.UserID

	if primaryID == secondaryID {
		return fmt.Errorf("identitylink: cannot merge a user into themselves")
	}

	// Verify the secondary user exists.
	if _, err := s.storage.UserByID(ctx, secondaryID); err != nil {
		return fmt.Errorf("identitylink: secondary user not found: %w", err)
	}

	// Move all authentication methods.
	oauths, err := s.storage.OAuthAccountsByUserID(ctx, secondaryID)
	if err != nil {
		return fmt.Errorf("identitylink: list secondary oauth accounts: %w", err)
	}
	for _, oa := range oauths {
		if err := s.storage.MoveOAuthAccount(ctx, oa.Provider, oa.ProviderUserID, primaryID); err != nil {
			return fmt.Errorf("identitylink: move oauth account %s/%s: %w", oa.Provider, oa.ProviderUserID, err)
		}
	}

	if err := s.storage.MovePasswordHash(ctx, primaryID, secondaryID); err != nil {
		return fmt.Errorf("identitylink: move password hash: %w", err)
	}

	if err := s.storage.MoveWebAuthnCredentials(ctx, primaryID, secondaryID); err != nil {
		return fmt.Errorf("identitylink: move webauthn credentials: %w", err)
	}

	if err := s.storage.MoveTOTPSecret(ctx, primaryID, secondaryID); err != nil {
		return fmt.Errorf("identitylink: move totp secret: %w", err)
	}

	// Revoke all sessions of the secondary user.
	if err := s.storage.RevokeUserSessions(ctx, secondaryID); err != nil {
		return fmt.Errorf("identitylink: revoke secondary sessions: %w", err)
	}

	meta := map[string]any{
		"primary_user_id":   primaryID.String(),
		"secondary_user_id": secondaryID.String(),
	}
	if input.AuditReason != "" {
		meta["reason"] = input.AuditReason
	}

	s.auditEm.EmitAudit(ctx, "account.merged", models.TargetRef{Type: "user", ID: primaryID.String()}, meta)
	s.auditEm.EmitAudit(ctx, "account.merged", models.TargetRef{Type: "user", ID: secondaryID.String()}, map[string]any{
		"merged_into": primaryID.String(),
	})

	return nil
}

// UnlinkOAuthProvider removes a provider from the user's account. It returns ErrLastAuthMethod when
// that is the only method left.
func (s *Service) UnlinkOAuthProvider(ctx context.Context, sessionToken, provider string) error {
	sess, err := s.requireFullSession(ctx, sessionToken)
	if err != nil {
		return err
	}

	count, err := s.authMethodCount(ctx, sess.UserID)
	if err != nil {
		return err
	}
	if count <= 1 {
		return models.ErrLastAuthMethod
	}

	if err := s.storage.DeleteOAuthAccountByProvider(ctx, sess.UserID, provider); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return fmt.Errorf("identitylink: provider %q not linked to user", provider)
		}
		return fmt.Errorf("identitylink: delete oauth account: %w", err)
	}

	s.auditEm.EmitAudit(ctx, "identity.unlinked", models.TargetRef{Type: "user", ID: sess.UserID.String()}, map[string]any{
		"provider": provider,
		"method":   "oauth",
	})
	return nil
}

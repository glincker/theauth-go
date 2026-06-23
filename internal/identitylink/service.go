// Package identitylink owns the three identity-linking service methods
// (v2.3): LinkOAuthToCurrentUser, LinkPasswordToCurrentUser, MergeAccounts.
// All three require a fully-authenticated session (AuthLevel = "full") and
// emit structured audit events.
//
// The package declares its own Storage and SessionStore interfaces so it can
// be constructed without importing the root theauth package (which would
// create an import cycle). The root *TheAuth wires the concrete adapters in.
package identitylink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
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

// requireFullSession verifies that the session resolved from sessionToken is
// fully authenticated (AuthLevel = "full"). Returns ErrStepUpRequired when
// the session is pending_2fa or missing, or the resolved session on success.
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

// authMethodCount returns the total number of authentication methods bound to
// userID: one for a confirmed password, one per linked OAuth provider, one per
// WebAuthn credential, one for a confirmed TOTP secret.
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

// LinkOAuthToCurrentUser binds an already-exchanged OAuth account to the
// currently-authenticated user. providerName and providerUserID identify the
// OAuth row. The caller (handler layer) is responsible for running the full
// OAuth authorization-code flow and extracting the provider user ID before
// calling this method.
//
// If the OAuth account is already linked to a different user an
// *IdentityConflictError (wrapping ErrIdentityConflict) is returned.
//
// Returns ErrStepUpRequired when sessionToken resolves to a pending_2fa or
// otherwise incomplete session.
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

// LinkPasswordToCurrentUser adds email+password as a backup authentication
// method for the currently-authenticated user. The new password is hashed
// with Argon2id using the same parameters as the password.Service.
//
// Returns ErrStepUpRequired when sessionToken resolves to a pending_2fa or
// otherwise incomplete session.
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

// MergeAccounts moves all authentication methods (OAuth accounts, password,
// WebAuthn credentials, TOTP secret) from secondaryID to primaryID, revokes
// all sessions of the secondary user, and emits audit events.
//
// primaryID must be the authenticated user's ID (the session resolved from
// sessionToken). secondaryID must be a different user.
//
// Returns ErrStepUpRequired when sessionToken is not fully authenticated.
// Returns an error when primaryID and secondaryID are equal.
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

// UnlinkOAuthProvider removes the named provider from the current user's
// account. Returns ErrLastAuthMethod when the provider is the only
// authentication method remaining.
//
// Returns ErrStepUpRequired when sessionToken is not fully authenticated.
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

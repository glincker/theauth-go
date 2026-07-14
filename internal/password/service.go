// Package password owns the email + password signup / signin / reset flow,
// including the Argon2id hash + verify cost (paid even on user-not-found to
// equalise signin timing per security audit M6), the magic-link-backed
// reset, and the TOTP-step-up gate that mints a pending_2fa session when
// the user has a confirmed second factor.
//
// Extracted from root service_password.go in PR D of the 2026-06
// architecture reorg. The root *theauth.TheAuth holds a *Service and
// exposes signupWithPassword / signinWithPassword /
// requestPasswordReset / resetPassword / requestPasswordResetForTest as
// thin forwarders so the v0.2 public surface is unchanged.
//
// The dummyPasswordHash is computed once in NewService so the verify cost
// is paid at startup, not per request. Without it, an attacker can time
// the signin response and learn which emails are registered.
package password

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// hashEmailForAudit returns sha256(lowercase(email)) hex-encoded. Inlined
// here (rather than reused from root) so this package does not import
// theauth.HashEmailForAudit (which would form an import cycle). Identical
// algorithm; tests are reused from root.
func hashEmailForAudit(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// MinPasswordLength is enforced at the library level (NIST 2024 baseline).
// No composition rules; NIST recommends against them. Consumers wanting
// stricter policies should layer them on top.
const MinPasswordLength = 12

// PasswordResetTTL is how long a reset token stays valid after issuance.
// Reset tokens are single-use; this is also enforced atomically in storage.
const PasswordResetTTL = time.Hour

// SigninStep is the v0.5 indicator returned alongside the session token by
// Signin: "full" when the cookie is immediately usable, "totp_required"
// when the cookie is a pending_2fa session that can only hit
// /auth/totp/verify and /auth/totp/recovery.
type SigninStep string

const (
	SigninStepFull         SigninStep = "full"
	SigninStepTOTPRequired SigninStep = "totp_required"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/password does not import the
// root theauth package and the constructor cycle stays broken.
type Storage interface {
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	SetUserPassword(ctx context.Context, userID models.ULID, passwordHash string) error
	UserByEmailWithPassword(ctx context.Context, email string) (user *models.User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t models.PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*models.PasswordResetToken, error)
	RevokeUserSessions(ctx context.Context, userID models.ULID) error
	TOTPSecretByUserID(ctx context.Context, userID models.ULID) (*models.TOTPSecret, error)
}

// SessionIssuer abstracts the session.Issue call. Allows password to mint
// a session at signup / signin time without importing internal/session.
type SessionIssuer interface {
	Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error)
}

// MagicLinkRequester abstracts the magiclink.RequestForTest call so signup
// can fire a verification email without importing internal/magiclink. The
// "ForTest" variant returns the raw token; we discard it (signup just
// needs the email to be sent) but we use this variant so we know whether
// the underlying call short-circuited on an unknown email.
type MagicLinkRequester interface {
	RequestForTest(ctx context.Context, email string) (string, error)
}

// PendingTOTPIssuer abstracts the IssuePending2FA call so signin can mint
// a pending_2fa session when the user has a confirmed second factor.
// Implemented by *totp.Service.
type PendingTOTPIssuer interface {
	IssuePending2FA(ctx context.Context, userID models.ULID, userAgent, ip string) (string, models.Session, error)
}

// Config bundles the runtime knobs Service needs. All fields are required.
type Config struct {
	// BaseURL prefixes the reset link in outbound email. Required.
	BaseURL string
	// TOTPEnabled mirrors root cfg.TOTP != nil. When false, Signin never
	// peeks at TOTPSecretByUserID and always mints a full session.
	TOTPEnabled bool
}

// Service holds the dependencies needed for password flows.
type Service struct {
	storage     Storage
	sender      email.Sender
	sessions    SessionIssuer
	magicLinks  MagicLinkRequester
	totpPending PendingTOTPIssuer
	auditEm     audit.Emitter
	cfg         Config
	dummyHash   string
}

// NewService constructs a password Service. dummyPasswordHash is computed
// once here so the verify cost is paid at startup, not per request (see
// security audit M6 2026-06-20). em may be nil; the constructor swaps in
// audit.NoopEmitter. totpPending may be nil only when cfg.TOTPEnabled is
// false; Signin would otherwise hit a nil-pointer dereference on the
// step-up path.
func NewService(
	storage Storage,
	sender email.Sender,
	sessions SessionIssuer,
	magicLinks MagicLinkRequester,
	totpPending PendingTOTPIssuer,
	em audit.Emitter,
	cfg Config,
) (*Service, error) {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	dummy, err := crypto.HashPassword("theauth-dummy-password-not-real")
	if err != nil {
		return nil, fmt.Errorf("theauth: synthesize signin timing-equalization hash: %w", err)
	}
	return &Service{
		storage:     storage,
		sender:      sender,
		sessions:    sessions,
		magicLinks:  magicLinks,
		totpPending: totpPending,
		auditEm:     em,
		cfg:         cfg,
		dummyHash:   dummy,
	}, nil
}

// DummyHash returns the precomputed Argon2id PHC string the Service uses
// for signin timing equalization. Exposed so the root *TheAuth can keep
// the legacy dummyPasswordHash field non-empty for any other timing path
// that may want to reuse it; not part of any caller-facing contract.
func (s *Service) DummyHash() string {
	return s.dummyHash
}

// normalizeEmail trims and lowercases an email for storage-side uniqueness.
func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// ValidateEmail wraps mail.ParseAddress and returns the normalized form
// when the input is a syntactically valid address. Exposed for the
// fuzz-test seam in the root export_test.go.
func ValidateEmail(raw string) (string, error) {
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return "", err
	}
	return normalizeEmail(addr.Address), nil
}

// Signup creates a new user with email + password credentials and issues a
// session. Also fires a magic-link verification email (best-effort).
// Returns CodeEmailTaken if the email is already registered, CodeWeakPassword
// if the password is below MinPasswordLength, and surfaces storage errors as-is.
func (s *Service) Signup(ctx context.Context, emailAddr, password string) (*models.User, string, error) {
	addr, err := mail.ParseAddress(emailAddr)
	if err != nil {
		return nil, "", models.NewError(models.CodeInvalidCredentials, "invalid email", err)
	}
	emailAddr = normalizeEmail(addr.Address)
	if len(password) < MinPasswordLength {
		return nil, "", models.NewError(models.CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", MinPasswordLength), nil)
	}

	if existing, err := s.storage.UserByEmail(ctx, emailAddr); err == nil && existing != nil {
		return nil, "", models.NewError(models.CodeEmailTaken, "email already registered", nil)
	} else if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
		return nil, "", err
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	user, err := s.storage.CreateUser(ctx, models.User{
		ID:        ulid.New(),
		Email:     emailAddr,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, "", err
	}
	if err := s.storage.SetUserPassword(ctx, user.ID, hash); err != nil {
		return nil, "", err
	}

	sessToken, _, err := s.sessions.Issue(ctx, user, "", "")
	if err != nil {
		return nil, "", err
	}

	// Best-effort verification email. Do not fail signup on email outages;
	// the user has a valid session and just lacks a clickable verify link
	// until they request a fresh one.
	if _, err := s.magicLinks.RequestForTest(ctx, emailAddr); err != nil {
		slog.Warn("theauth: signup verification email failed", "email", emailAddr, "err", err.Error())
	}

	s.auditEm.EmitAudit(ctx, "user.login", models.TargetRef{Type: "user", ID: user.ID.String()}, map[string]any{
		"auth_method": "password",
		"email_hash":  hashEmailForAudit(emailAddr),
	})
	slog.Info("theauth: password signup", "user_id", user.ID.String(), "email", emailAddr)
	return &user, sessToken, nil
}

// Signin verifies credentials and issues a session. Always returns
// CodeInvalidCredentials for "no such user" AND "wrong password" so callers
// can't enumerate registered emails. Returns the session token, user, and
// a step indicator: when the user has a confirmed TOTP secret the step is
// "totp_required" and the session is pending_2fa instead of full.
func (s *Service) Signin(ctx context.Context, emailAddr, password, userAgent, ip string) (string, *models.User, SigninStep, error) {
	emailAddr = normalizeEmail(emailAddr)
	user, hash, err := s.storage.UserByEmailWithPassword(ctx, emailAddr)
	if errors.Is(err, models.ErrStorageNotFound) {
		// security audit M6 (2026-06-20): pay the Argon2id verify cost
		// on the user-not-found branch too. Without this, an attacker
		// can time the response and learn which emails are registered.
		// The dummy hash mints once at NewService time; the verify
		// result is ignored.
		_, _ = crypto.VerifyPassword(password, s.dummyHash)
		return "", nil, "", models.NewError(models.CodeInvalidCredentials, "invalid email or password", nil)
	}
	if err != nil {
		return "", nil, "", err
	}
	if hash == "" {
		// Account exists but has no password set (magic-link-only signup).
		// Pay the verify cost against the dummy hash so the timing matches
		// the genuine wrong-password branch (security audit M6).
		_, _ = crypto.VerifyPassword(password, s.dummyHash)
		return "", nil, "", models.NewError(models.CodeInvalidCredentials, "invalid email or password", nil)
	}
	ok, err := crypto.VerifyPassword(password, hash)
	if err != nil {
		// Malformed stored hash; server-side fault, not a credential miss.
		slog.Error("theauth: stored password hash unparseable", "user_id", user.ID.String(), "err", err.Error())
		return "", nil, "", err
	}
	if !ok {
		return "", nil, "", models.NewError(models.CodeInvalidCredentials, "invalid email or password", nil)
	}
	// v0.5 step-up: when TOTP is enrolled and confirmed for this user, mint
	// a pending_2fa session instead of a full one. The caller (the HTTP
	// handler) renders {"step":"totp_required"} so the client knows to
	// prompt for the 6-digit code.
	if s.cfg.TOTPEnabled {
		secret, err := s.storage.TOTPSecretByUserID(ctx, user.ID)
		if err == nil && secret != nil && secret.ConfirmedAt != nil {
			pendTok, _, err := s.totpPending.IssuePending2FA(ctx, user.ID, userAgent, ip)
			if err != nil {
				return "", nil, "", err
			}
			slog.Info("theauth: password signin (pending 2fa)", "user_id", user.ID.String(), "email", emailAddr)
			return pendTok, user, SigninStepTOTPRequired, nil
		} else if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
			return "", nil, "", err
		}
	}
	sessToken, _, err := s.sessions.Issue(ctx, *user, userAgent, ip)
	if err != nil {
		return "", nil, "", err
	}
	s.auditEm.EmitAudit(audit.WithAuditMetadata(ctx, audit.AuditMetadata{ActorUserID: &user.ID, IP: ip, UserAgent: userAgent}),
		"user.login", models.TargetRef{Type: "user", ID: user.ID.String()}, map[string]any{
			"auth_method": "password",
			"email_hash":  hashEmailForAudit(emailAddr),
		})
	slog.Info("theauth: password signin", "user_id", user.ID.String(), "email", emailAddr)
	return sessToken, user, SigninStepFull, nil
}

// RequestReset always returns nil error on "user does not exist" to prevent
// email enumeration. When the user does exist, mints a single-use token
// and emails the reset link.
func (s *Service) RequestReset(ctx context.Context, emailAddr string) error {
	_, err := s.RequestResetForTest(ctx, emailAddr)
	return err
}

// RequestResetForTest is the testable variant: returns the raw token when
// one is minted, "" when the email does not exist (so tests can assert the
// silent-no-op behavior). Production code calls RequestReset.
func (s *Service) RequestResetForTest(ctx context.Context, emailAddr string) (string, error) {
	emailAddr = normalizeEmail(emailAddr)
	user, err := s.storage.UserByEmail(ctx, emailAddr)
	if errors.Is(err, models.ErrStorageNotFound) {
		// Silent success; do not disclose whether the email is registered.
		slog.Info("theauth: password reset requested for unknown email", "email", emailAddr)
		return "", nil
	}
	if err != nil {
		return "", err
	}

	token, err := crypto.NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	rt := models.PasswordResetToken{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: crypto.HashToken(token),
		ExpiresAt: now.Add(PasswordResetTTL),
		CreatedAt: now,
	}
	if err := s.storage.CreatePasswordResetToken(ctx, rt); err != nil {
		return "", err
	}

	link := fmt.Sprintf("%s/auth/email-password/reset?token=%s", s.cfg.BaseURL, token)
	body := fmt.Sprintf("Reset your password: %s\n\nExpires in %s.", link, PasswordResetTTL)
	if err := s.sender.Send(ctx, emailAddr, "Reset your password", body); err != nil {
		// Best effort; token already minted. Log and continue.
		slog.Warn("theauth: password reset email send failed", "email", emailAddr, "err", err.Error())
	}
	s.auditEm.EmitAudit(ctx, "password.reset.requested", models.TargetRef{Type: "user", ID: user.ID.String()}, map[string]any{
		"email_hash": hashEmailForAudit(emailAddr),
	})
	slog.Info("theauth: password reset requested", "user_id", user.ID.String(), "email", emailAddr)
	return token, nil
}

// Reset atomically consumes a reset token, updates the user's password,
// and revokes all existing sessions. Returns CodePasswordResetInvalid on
// missing/unknown tokens, CodePasswordResetExpired on stale ones, and
// CodeWeakPassword on too-short new passwords. Returns the affected
// user's ID on success so callers can dispatch LifecycleHooks.OnPasswordChange.
func (s *Service) Reset(ctx context.Context, token, newPassword string) (models.ULID, error) {
	if token == "" {
		return models.ULID{}, models.NewError(models.CodePasswordResetInvalid, "missing token", nil)
	}
	if len(newPassword) < MinPasswordLength {
		return models.ULID{}, models.NewError(models.CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", MinPasswordLength), nil)
	}

	rt, err := s.storage.ConsumePasswordResetToken(ctx, crypto.HashToken(token))
	if errors.Is(err, models.ErrStorageNotFound) {
		return models.ULID{}, models.NewError(models.CodePasswordResetInvalid, "invalid or already-used token", nil)
	}
	if err != nil {
		return models.ULID{}, err
	}
	// ConsumePasswordResetToken already enforces expires_at > now() in SQL,
	// but the in-memory adapter mirrors the same filter. Defensive
	// double-check for forward-compat with future storage backends.
	if rt.ExpiresAt.Before(time.Now()) {
		return models.ULID{}, models.NewError(models.CodePasswordResetExpired, "reset token expired", nil)
	}

	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return models.ULID{}, err
	}
	if err := s.storage.SetUserPassword(ctx, rt.UserID, hash); err != nil {
		return models.ULID{}, err
	}
	if err := s.storage.RevokeUserSessions(ctx, rt.UserID); err != nil {
		// Non-fatal: log so ops know revocation did not complete, but the
		// password change DID succeed.
		slog.Warn("theauth: revoke sessions after password reset failed", "user_id", rt.UserID.String(), "err", err.Error())
	}
	s.auditEm.EmitAudit(ctx, "password.reset.completed", models.TargetRef{Type: "user", ID: rt.UserID.String()}, nil)
	s.auditEm.EmitAudit(ctx, "password.changed", models.TargetRef{Type: "user", ID: rt.UserID.String()}, nil)
	slog.Info("theauth: password reset", "user_id", rt.UserID.String())
	return rt.UserID, nil
}

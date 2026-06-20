package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// MinPasswordLength is enforced at the library level (NIST 2024 baseline).
// No composition rules — NIST recommends against them. Consumers wanting
// stricter policies should layer them on top.
const MinPasswordLength = 12

// PasswordResetTTL is how long a reset token stays valid after issuance.
// Reset tokens are single-use; this is also enforced atomically in storage.
const PasswordResetTTL = time.Hour

// normalizeEmail trims and lowercases an email for storage-side uniqueness.
// Email parsing happens at the handler edge; this is the canonicalization step.
func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// signupWithPassword creates a new user with email + password credentials and
// issues a session. Also fires a magic-link verification email (best-effort).
// Returns CodeEmailTaken if the email is already registered, CodeWeakPassword
// if the password is below MinPasswordLength, and surfaces storage errors as-is.
func (a *TheAuth) signupWithPassword(ctx context.Context, emailAddr, password string) (*User, string, error) {
	addr, err := mail.ParseAddress(emailAddr)
	if err != nil {
		return nil, "", NewError(CodeInvalidCredentials, "invalid email", err)
	}
	emailAddr = normalizeEmail(addr.Address)
	if len(password) < MinPasswordLength {
		return nil, "", NewError(CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", MinPasswordLength), nil)
	}

	// Email-taken check. We do a UserByEmail lookup; if a hit, return the
	// stable taken-code so the handler can map to 409 without disclosing
	// hash presence (unverified vs verified accounts both count as taken).
	if existing, err := a.storage.UserByEmail(ctx, emailAddr); err == nil && existing != nil {
		return nil, "", NewError(CodeEmailTaken, "email already registered", nil)
	} else if err != nil && !errors.Is(err, ErrStorageNotFound) {
		return nil, "", err
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	user, err := a.storage.CreateUser(ctx, User{
		ID:        ulid.New(),
		Email:     emailAddr,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, "", err
	}
	if err := a.storage.SetUserPassword(ctx, user.ID, hash); err != nil {
		return nil, "", err
	}

	sessToken, _, err := a.issueSession(ctx, user, "", "")
	if err != nil {
		return nil, "", err
	}

	// Best-effort verification email. Don't fail signup on email outages —
	// the user has a valid session; they just won't have a clickable verify
	// link until they request a fresh one.
	if _, err := a.requestMagicLinkForTest(ctx, emailAddr); err != nil {
		slog.Warn("theauth: signup verification email failed", "email", emailAddr, "err", err.Error())
	}

	slog.Info("theauth: password signup", "user_id", user.ID.String(), "email", emailAddr)
	return &user, sessToken, nil
}

// signinWithPassword verifies credentials and issues a session. Always returns
// CodeInvalidCredentials for "no such user" AND "wrong password" so callers
// can't enumerate registered emails. Returns the session token + user on
// success.
func (a *TheAuth) signinWithPassword(ctx context.Context, emailAddr, password, userAgent, ip string) (string, *User, error) {
	emailAddr = normalizeEmail(emailAddr)
	user, hash, err := a.storage.UserByEmailWithPassword(ctx, emailAddr)
	if errors.Is(err, ErrStorageNotFound) {
		return "", nil, NewError(CodeInvalidCredentials, "invalid email or password", nil)
	}
	if err != nil {
		return "", nil, err
	}
	if hash == "" {
		// Account exists but has no password set (magic-link-only signup).
		// Indistinguishable from "wrong password" to avoid enumeration.
		return "", nil, NewError(CodeInvalidCredentials, "invalid email or password", nil)
	}
	ok, err := crypto.VerifyPassword(password, hash)
	if err != nil {
		// Malformed stored hash — server-side fault, not a credential miss.
		slog.Error("theauth: stored password hash unparseable", "user_id", user.ID.String(), "err", err.Error())
		return "", nil, err
	}
	if !ok {
		return "", nil, NewError(CodeInvalidCredentials, "invalid email or password", nil)
	}
	sessToken, _, err := a.issueSession(ctx, *user, userAgent, ip)
	if err != nil {
		return "", nil, err
	}
	slog.Info("theauth: password signin", "user_id", user.ID.String(), "email", emailAddr)
	return sessToken, user, nil
}

// requestPasswordReset always returns nil error on "user does not exist" to
// prevent email enumeration. When the user does exist, mints a single-use
// token and emails the reset link.
func (a *TheAuth) requestPasswordReset(ctx context.Context, emailAddr string) error {
	_, err := a.requestPasswordResetForTest(ctx, emailAddr)
	return err
}

// requestPasswordResetForTest is the testable variant — returns the raw token
// when one is minted, "" when the email doesn't exist (so tests can assert the
// silent-no-op behavior). Production code calls requestPasswordReset.
func (a *TheAuth) requestPasswordResetForTest(ctx context.Context, emailAddr string) (string, error) {
	emailAddr = normalizeEmail(emailAddr)
	user, err := a.storage.UserByEmail(ctx, emailAddr)
	if errors.Is(err, ErrStorageNotFound) {
		// Silent success — don't disclose whether the email is registered.
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
	rt := PasswordResetToken{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: crypto.HashToken(token),
		ExpiresAt: now.Add(PasswordResetTTL),
		CreatedAt: now,
	}
	if err := a.storage.CreatePasswordResetToken(ctx, rt); err != nil {
		return "", err
	}

	link := fmt.Sprintf("%s/auth/email-password/reset?token=%s", a.baseURL, token)
	body := fmt.Sprintf("Reset your password: %s\n\nExpires in %s.", link, PasswordResetTTL)
	if err := a.emailSender.Send(ctx, emailAddr, "Reset your password", body); err != nil {
		// Best effort — token already minted; log and continue.
		slog.Warn("theauth: password reset email send failed", "email", emailAddr, "err", err.Error())
	}
	slog.Info("theauth: password reset requested", "user_id", user.ID.String(), "email", emailAddr)
	return token, nil
}

// resetPassword atomically consumes a reset token, updates the user's password,
// and revokes all existing sessions. Returns CodePasswordResetInvalid on
// missing/unknown tokens, CodePasswordResetExpired on stale ones, and
// CodeWeakPassword on too-short new passwords.
func (a *TheAuth) resetPassword(ctx context.Context, token, newPassword string) error {
	if token == "" {
		return NewError(CodePasswordResetInvalid, "missing token", nil)
	}
	if len(newPassword) < MinPasswordLength {
		return NewError(CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", MinPasswordLength), nil)
	}

	rt, err := a.storage.ConsumePasswordResetToken(ctx, crypto.HashToken(token))
	if errors.Is(err, ErrStorageNotFound) {
		return NewError(CodePasswordResetInvalid, "invalid or already-used token", nil)
	}
	if err != nil {
		return err
	}
	// ConsumePasswordResetToken already enforces expires_at > now() in SQL,
	// but the in-memory adapter mirrors the same filter. Defensive double-check
	// for forward-compat with future storage backends.
	if rt.ExpiresAt.Before(time.Now()) {
		return NewError(CodePasswordResetExpired, "reset token expired", nil)
	}

	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := a.storage.SetUserPassword(ctx, rt.UserID, hash); err != nil {
		return err
	}
	// Revoke every existing session for this user — best practice on reset.
	if err := a.storage.RevokeUserSessions(ctx, rt.UserID); err != nil {
		// Non-fatal: log so ops know revocation didn't complete, but the
		// password change DID succeed.
		slog.Warn("theauth: revoke sessions after password reset failed", "user_id", rt.UserID.String(), "err", err.Error())
	}
	slog.Info("theauth: password reset", "user_id", rt.UserID.String())
	return nil
}

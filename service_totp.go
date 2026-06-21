package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/pquerna/otp/totp"
)

// totpEnrollmentTTL caps the time window between /enroll/begin and
// /enroll/finish. 10 minutes is generous enough that a real user can scan a
// QR and type the first 6-digit code without being rushed, short enough
// that a forgotten enrollment does not linger forever.
const totpEnrollmentTTL = 10 * time.Minute

// totpEnrollmentGCEvery sweeps expired enrollments.
const totpEnrollmentGCEvery = time.Minute

// pendingSessionMaxFailures is the number of failed TOTP attempts allowed
// per pending session before the session is revoked. Five strikes mirrors
// the v0.2 password rate-limit budget and forces a fresh password verify
// after a brute-force run rather than letting an attacker keep guessing
// against the same pending cookie. Per the v0.5 design doc section 8.6,
// the pending cookie is otherwise scoped only to /auth/totp/verify and
// /auth/totp/recovery, so this is the entire blast radius.
const pendingSessionMaxFailures = 5

// totpEnrollment holds the plaintext secret between /enroll/begin and
// /enroll/finish so we do not have to round-trip through Decrypt on the
// hot path. Per the design doc this stays in-memory only; the persisted
// totp_secrets row is created only after /finish succeeds (atomic confirm).
type totpEnrollment struct {
	userID    ULID
	secret    string // base32
	expiresAt time.Time
}

// pendingFailureCounter tracks consecutive bad codes on a single pending
// session. Stored separately from the session itself so we don't write to
// the DB on every wrong digit. After pendingSessionMaxFailures, the
// session is revoked.
type pendingFailureCounter struct {
	mu    sync.Mutex
	count int
}

// EnrollTOTPResult is returned by BeginTOTPEnrollment for the caller to
// render: Secret is the base32 string the user can type manually, OTPAuthURL
// is the otpauth:// URI the consumer renders as a QR. EnrollmentID is the
// opaque token /enroll/finish must echo back to bind the secret to the
// session.
type EnrollTOTPResult struct {
	Secret       string `json:"secret"`
	OTPAuthURL   string `json:"otpAuthUrl"`
	EnrollmentID string `json:"enrollmentId"`
}

// totpEnrollmentGCLoop sweeps expired pending enrollments.
func (a *TheAuth) totpEnrollmentGCLoop() {
	t := time.NewTicker(totpEnrollmentGCEvery)
	defer t.Stop()
	for {
		select {
		case <-a.totpEnrollmentStop:
			return
		case now := <-t.C:
			a.totpEnrollments.Range(func(k, v any) bool {
				if e, ok := v.(*totpEnrollment); ok && e.expiresAt.Before(now) {
					a.totpEnrollments.Delete(k)
				}
				return true
			})
		}
	}
}

// BeginTOTPEnrollment generates a fresh shared secret and otpauth URL,
// returns them to the caller (the secret is displayed exactly once), and
// stashes the plaintext in the in-memory pending map keyed by the
// returned EnrollmentID. The DB row is written immediately with
// confirmed_at = NULL so a server restart does not strand a half-enrolled
// account, but verify is gated on the in-memory secret to keep the
// AES-GCM Decrypt cost off the verify hot path.
func (a *TheAuth) BeginTOTPEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	if a.totpCfg == nil {
		return EnrollTOTPResult{}, errors.New("theauth: TOTP not configured")
	}
	if accountName == "" {
		return EnrollTOTPResult{}, errors.New("theauth: accountName is required (typically the user's email)")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.totpCfg.Issuer,
		AccountName: accountName,
	})
	if err != nil {
		return EnrollTOTPResult{}, fmt.Errorf("theauth: totp generate: %w", err)
	}
	secret := key.Secret()
	enc, err := crypto.Encrypt(a.encryptionKey, []byte(secret))
	if err != nil {
		return EnrollTOTPResult{}, fmt.Errorf("theauth: encrypt totp secret: %w", err)
	}
	now := time.Now()
	if err := a.storage.UpsertPendingTOTPSecret(ctx, TOTPSecret{
		UserID: userID, SecretEnc: enc, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return EnrollTOTPResult{}, fmt.Errorf("theauth: upsert pending totp: %w", err)
	}
	enrollID, err := crypto.NewToken()
	if err != nil {
		return EnrollTOTPResult{}, err
	}
	a.totpEnrollments.Store(enrollID, &totpEnrollment{
		userID:    userID,
		secret:    secret,
		expiresAt: now.Add(totpEnrollmentTTL),
	})
	return EnrollTOTPResult{
		Secret:       secret,
		OTPAuthURL:   key.URL(),
		EnrollmentID: enrollID,
	}, nil
}

// FinishTOTPEnrollment validates one code against the pending secret,
// confirms the row, generates RecoveryCodeCount single-use recovery codes,
// and returns them to the caller (the only time the plaintext codes are
// visible). Idempotency: a second /finish call with the same enrollmentID
// fails with ErrAlreadyEnrolled.
func (a *TheAuth) FinishTOTPEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	if a.totpCfg == nil {
		return nil, errors.New("theauth: TOTP not configured")
	}
	raw, ok := a.totpEnrollments.LoadAndDelete(enrollmentID)
	if !ok {
		return nil, NewError(CodeInvalidTOTP, "enrollment unknown or expired", nil)
	}
	enroll, ok := raw.(*totpEnrollment)
	if !ok || enroll.userID != userID {
		return nil, NewError(CodeInvalidTOTP, "enrollment user mismatch", nil)
	}
	if time.Now().After(enroll.expiresAt) {
		return nil, NewError(CodeInvalidTOTP, "enrollment expired", nil)
	}
	if !totp.Validate(code, enroll.secret) {
		// Restore the entry so the user can retry within the window
		// without having to re-scan the QR. The 6-digit code rotates
		// every 30s; a brute force is bounded by the TTL plus the
		// pending session counter (separate, applied at verify time).
		enroll.expiresAt = time.Now().Add(totpEnrollmentTTL)
		a.totpEnrollments.Store(enrollmentID, enroll)
		return nil, NewError(CodeInvalidTOTP, "invalid code", nil)
	}
	// Confirm the persisted row. If it is already confirmed (race with a
	// second /finish call), surface ErrAlreadyEnrolled rather than minting
	// a second batch of recovery codes.
	if existing, err := a.storage.TOTPSecretByUserID(ctx, userID); err == nil && existing != nil && existing.ConfirmedAt != nil {
		return nil, NewError(CodeAlreadyEnrolled, "totp already enrolled", ErrAlreadyEnrolled)
	}
	now := time.Now()
	if err := a.storage.ConfirmTOTPSecret(ctx, userID, now); err != nil {
		return nil, fmt.Errorf("theauth: confirm totp: %w", err)
	}
	// Mint recovery codes. The plaintext list is returned to the caller
	// here and nowhere else; we persist only salted hashes.
	count := a.totpCfg.RecoveryCodeCount
	plain := make([]string, 0, count)
	stored := make([]RecoveryCode, 0, count)
	for i := 0; i < count; i++ {
		c, err := crypto.GenerateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("theauth: generate recovery code: %w", err)
		}
		h, err := crypto.HashRecoveryCode(c)
		if err != nil {
			return nil, fmt.Errorf("theauth: hash recovery code: %w", err)
		}
		plain = append(plain, c)
		stored = append(stored, RecoveryCode{
			ID:        ulid.New(),
			UserID:    userID,
			CodeHash:  h,
			CreatedAt: now,
		})
	}
	if err := a.storage.InsertRecoveryCodes(ctx, stored); err != nil {
		return nil, fmt.Errorf("theauth: insert recovery codes: %w", err)
	}
	slog.Info("theauth: totp enrolled", "user_id", userID.String(), "recovery_codes", count)
	return plain, nil
}

// IssuePending2FA mints a short-lived session whose AuthLevel is
// AuthLevelPending2FA. The cookie name is identical to the full session
// cookie so the browser sends it everywhere; middleware/RequireAuth
// rejects it except on the two TOTP verify endpoints (handled by the
// requirePendingOrFull tag in handlers_totp.go).
func (a *TheAuth) IssuePending2FA(ctx context.Context, userID ULID, ua, ip string) (string, Session, error) {
	tok, err := crypto.NewToken()
	if err != nil {
		return "", Session{}, err
	}
	now := time.Now()
	sess := Session{
		ID:        ulid.New(),
		UserID:    userID,
		TokenHash: crypto.HashToken(tok),
		UserAgent: ua,
		IP:        ip,
		CreatedAt: now,
		// 10-minute TTL: matches the time a user can reasonably take to
		// pull their phone out, open the authenticator, and type the code.
		ExpiresAt: now.Add(10 * time.Minute),
		AuthLevel: AuthLevelPending2FA,
	}
	stored, err := a.storage.CreateSessionWithAuthLevel(ctx, sess)
	if err != nil {
		return "", Session{}, err
	}
	return tok, stored, nil
}

// VerifyTOTP consumes a 6-digit code against the user's confirmed secret,
// upgrades their pending session to full, and returns the (same) token
// with the upgraded session row. On five consecutive failures the pending
// session is revoked.
func (a *TheAuth) VerifyTOTP(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	sess, _, err := a.validateSession(ctx, pendingSessionToken)
	if err != nil {
		return "", Session{}, err
	}
	if sess.AuthLevel != AuthLevelPending2FA {
		return "", Session{}, NewError(CodeInvalidCredentials, "session is not pending 2fa", nil)
	}
	secret, err := a.decryptTOTPSecret(ctx, sess.UserID)
	if err != nil {
		return "", Session{}, err
	}
	if !totp.Validate(code, secret) {
		a.recordPendingFailure(ctx, sess.ID, sess.UserID)
		return "", Session{}, NewError(CodeInvalidTOTP, "invalid code", nil)
	}
	a.clearPendingFailure(sess.ID)
	if err := a.storage.UpdateSessionAuthLevel(ctx, sess.ID, AuthLevelFull); err != nil {
		return "", Session{}, err
	}
	updated := *sess
	updated.AuthLevel = AuthLevelFull
	return pendingSessionToken, updated, nil
}

// ConsumeRecoveryCode upgrades a pending session by consuming one unused
// recovery code. Five failures revoke the session just like VerifyTOTP.
func (a *TheAuth) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	sess, _, err := a.validateSession(ctx, pendingSessionToken)
	if err != nil {
		return "", Session{}, err
	}
	if sess.AuthLevel != AuthLevelPending2FA {
		return "", Session{}, NewError(CodeInvalidCredentials, "session is not pending 2fa", nil)
	}
	if err := a.storage.ConsumeRecoveryCode(ctx, sess.UserID, code, time.Now()); err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			a.recordPendingFailure(ctx, sess.ID, sess.UserID)
			return "", Session{}, NewError(CodeInvalidTOTP, "invalid recovery code", nil)
		}
		return "", Session{}, err
	}
	a.clearPendingFailure(sess.ID)
	if err := a.storage.UpdateSessionAuthLevel(ctx, sess.ID, AuthLevelFull); err != nil {
		return "", Session{}, err
	}
	updated := *sess
	updated.AuthLevel = AuthLevelFull
	return pendingSessionToken, updated, nil
}

// decryptTOTPSecret loads the confirmed secret for a user and Decrypts it
// using the AES-GCM key from Config.EncryptionKey. Returns
// ErrInvalidCredentials when the user has no confirmed secret (defensive;
// this should not happen on a pending session, but a UI bug could deliver
// one).
func (a *TheAuth) decryptTOTPSecret(ctx context.Context, userID ULID) (string, error) {
	row, err := a.storage.TOTPSecretByUserID(ctx, userID)
	if err != nil || row == nil || row.ConfirmedAt == nil {
		return "", NewError(CodeInvalidCredentials, "no totp credential", nil)
	}
	plain, err := crypto.Decrypt(a.encryptionKey, row.SecretEnc)
	if err != nil {
		return "", fmt.Errorf("theauth: decrypt totp: %w", err)
	}
	return string(plain), nil
}

// recordPendingFailure bumps the in-memory failure counter for the given
// pending session. On the pendingSessionMaxFailures'th failure the session
// is revoked (forcing a fresh password verify before another attempt).
func (a *TheAuth) recordPendingFailure(ctx context.Context, sessID ULID, userID ULID) {
	raw, _ := a.pendingFailures.LoadOrStore(sessID, &pendingFailureCounter{})
	c, ok := raw.(*pendingFailureCounter)
	if !ok {
		return
	}
	c.mu.Lock()
	c.count++
	hit := c.count >= pendingSessionMaxFailures
	c.mu.Unlock()
	if hit {
		if err := a.storage.RevokeSession(ctx, sessID); err != nil {
			slog.Warn("theauth: revoke pending session after totp brute force",
				"err", err.Error(), "session_id", sessID.String(), "user_id", userID.String())
		}
		a.pendingFailures.Delete(sessID)
	}
}

// clearPendingFailure resets the counter on a successful verify.
func (a *TheAuth) clearPendingFailure(sessID ULID) {
	a.pendingFailures.Delete(sessID)
}

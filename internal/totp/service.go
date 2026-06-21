// Package totp owns the v0.5 second-factor TOTP surface: enrollment
// (BeginEnrollment + FinishEnrollment), verification (Verify), and the
// recovery-code path (ConsumeRecoveryCode). Also owns the pending_2fa
// session minted by Signin when the user has a confirmed second factor
// (IssuePending2FA) and the in-memory failure counter that revokes a
// pending session after five wrong codes.
//
// Extracted from root service_totp.go in PR D of the 2026-06 architecture
// reorg. The root *theauth.TheAuth holds a *Service and exposes
// BeginTOTPEnrollment / FinishTOTPEnrollment / VerifyTOTP /
// ConsumeRecoveryCode / IssuePending2FA as thin forwarders so the v0.5
// public surface is unchanged.
//
// The pending-enrollment map (totpEnrollments) and the pending-failure
// counter map (pendingFailures) live on the Service. The GC goroutine for
// expired enrollments starts in Start and stops in Stop; every "go ..."
// in this package has a matching stop path so there is no goroutine leak.
package totp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/pquerna/otp/totp"
)

// enrollmentTTL caps the time window between /enroll/begin and
// /enroll/finish. 10 minutes is generous enough for a user to scan a QR
// and type the first 6-digit code without being rushed, short enough that
// a forgotten enrollment does not linger forever.
const enrollmentTTL = 10 * time.Minute

// enrollmentGCEvery sweeps expired enrollments.
const enrollmentGCEvery = time.Minute

// pendingSessionMaxFailures is the number of failed TOTP attempts allowed
// per pending session before the session is revoked. Five strikes mirrors
// the v0.2 password rate-limit budget. After this many wrong codes the
// attacker is forced back to the password step.
const pendingSessionMaxFailures = 5

// EnrollResult is returned by BeginEnrollment for the caller to render.
// Secret is the base32 string the user can type manually, OTPAuthURL is
// the otpauth:// URI the consumer renders as a QR. EnrollmentID is the
// opaque token /enroll/finish must echo back to bind the secret to the
// session.
type EnrollResult struct {
	Secret       string `json:"secret"`
	OTPAuthURL   string `json:"otpAuthUrl"`
	EnrollmentID string `json:"enrollmentId"`
}

// enrollment holds the plaintext secret between /enroll/begin and
// /enroll/finish so we do not have to round-trip through Decrypt on the
// hot path. Per the v0.5 design doc this stays in-memory only; the
// persisted totp_secrets row is created only after /finish succeeds
// (atomic confirm).
type enrollment struct {
	userID    models.ULID
	secret    string // base32
	expiresAt time.Time
}

// failureCounter tracks consecutive bad codes on a single pending session.
// Stored separately from the session itself so we do not write to the DB
// on every wrong digit. After pendingSessionMaxFailures the session is
// revoked.
type failureCounter struct {
	mu    sync.Mutex
	count int
}

// Storage is the minimal persistence subset this package needs.
type Storage interface {
	UpsertPendingTOTPSecret(ctx context.Context, s models.TOTPSecret) error
	ConfirmTOTPSecret(ctx context.Context, userID models.ULID, at time.Time) error
	TOTPSecretByUserID(ctx context.Context, userID models.ULID) (*models.TOTPSecret, error)
	DeleteTOTPSecret(ctx context.Context, userID models.ULID) error
	InsertRecoveryCodes(ctx context.Context, codes []models.RecoveryCode) error
	ConsumeRecoveryCode(ctx context.Context, userID models.ULID, code string, at time.Time) error
	CreateSessionWithAuthLevel(ctx context.Context, s models.Session) (models.Session, error)
	UpdateSessionAuthLevel(ctx context.Context, id models.ULID, level string) error
	RevokeSession(ctx context.Context, id models.ULID) error
	SessionByTokenHash(ctx context.Context, hash []byte) (*models.Session, error)
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
}

// SessionValidator abstracts the session.Validate call so this package can
// upgrade a pending session without importing internal/session. The
// concrete *session.Service satisfies this interface naturally.
type SessionValidator interface {
	Validate(ctx context.Context, token string) (*models.Session, *models.User, error)
}

// Config wires the second-factor TOTP behavior. Mirrors root
// theauth.TOTPConfig field-for-field.
type Config struct {
	Issuer            string
	RecoveryCodeCount int
}

// Service holds the dependencies needed for TOTP flows.
type Service struct {
	storage       Storage
	sessions      SessionValidator
	auditEm       audit.Emitter
	cfg           *Config
	encryptionKey []byte

	// enrollments is the in-memory map of in-flight enrollments keyed by
	// the EnrollmentID returned from BeginEnrollment.
	enrollments sync.Map
	// pendingFailures tracks per-session failure counts for the verify
	// and recovery-code paths.
	pendingFailures sync.Map

	// stopGC signals the enrollment GC goroutine to exit. nil before
	// Start; closed by Stop. Idempotent via started/stopped flags.
	stopGC  chan struct{}
	started bool
	stopped bool
	mu      sync.Mutex // guards started / stopped / stopGC
}

// NewService constructs a TOTP Service. cfg may be nil; in that case every
// public method returns "TOTP not configured" matching the legacy root
// behavior. em may be nil; the constructor swaps in audit.NoopEmitter.
func NewService(storage Storage, sessions SessionValidator, em audit.Emitter, cfg *Config, encryptionKey []byte) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{
		storage:       storage,
		sessions:      sessions,
		auditEm:       em,
		cfg:           cfg,
		encryptionKey: encryptionKey,
	}
}

// Start spawns the enrollment GC goroutine. Idempotent: a second call is
// a no-op. No-op when cfg is nil.
func (s *Service) Start() {
	if s.cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	s.stopGC = make(chan struct{})
	go s.gcLoop(s.stopGC)
}

// Stop closes the stop channel and signals the GC goroutine to return.
// Idempotent: a second call is a no-op.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped {
		return
	}
	s.stopped = true
	if s.stopGC != nil {
		select {
		case <-s.stopGC:
		default:
			close(s.stopGC)
		}
	}
}

// gcLoop sweeps expired pending enrollments. Mirrors the v0.5 root
// totpEnrollmentGCLoop pattern.
func (s *Service) gcLoop(stop chan struct{}) {
	t := time.NewTicker(enrollmentGCEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.enrollments.Range(func(k, v any) bool {
				if e, ok := v.(*enrollment); ok && e.expiresAt.Before(now) {
					s.enrollments.Delete(k)
				}
				return true
			})
		}
	}
}

// BeginEnrollment generates a fresh shared secret and otpauth URL, returns
// them to the caller (the secret is displayed exactly once), and stashes
// the plaintext in the in-memory pending map keyed by the returned
// EnrollmentID. The DB row is written immediately with confirmed_at = NULL
// so a server restart does not strand a half-enrolled account, but verify
// is gated on the in-memory secret to keep the AES-GCM Decrypt cost off
// the verify hot path.
func (s *Service) BeginEnrollment(ctx context.Context, userID models.ULID, accountName string) (EnrollResult, error) {
	if s.cfg == nil {
		return EnrollResult{}, errors.New("theauth: TOTP not configured")
	}
	if accountName == "" {
		return EnrollResult{}, errors.New("theauth: accountName is required (typically the user's email)")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.Issuer,
		AccountName: accountName,
	})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("theauth: totp generate: %w", err)
	}
	secret := key.Secret()
	enc, err := crypto.Encrypt(s.encryptionKey, []byte(secret))
	if err != nil {
		return EnrollResult{}, fmt.Errorf("theauth: encrypt totp secret: %w", err)
	}
	now := time.Now()
	if err := s.storage.UpsertPendingTOTPSecret(ctx, models.TOTPSecret{
		UserID: userID, SecretEnc: enc, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return EnrollResult{}, fmt.Errorf("theauth: upsert pending totp: %w", err)
	}
	enrollID, err := crypto.NewToken()
	if err != nil {
		return EnrollResult{}, err
	}
	s.enrollments.Store(enrollID, &enrollment{
		userID:    userID,
		secret:    secret,
		expiresAt: now.Add(enrollmentTTL),
	})
	return EnrollResult{
		Secret:       secret,
		OTPAuthURL:   key.URL(),
		EnrollmentID: enrollID,
	}, nil
}

// FinishEnrollment validates one code against the pending secret, confirms
// the row, generates RecoveryCodeCount single-use recovery codes, and
// returns them to the caller (the only time the plaintext codes are
// visible). Idempotency: a second /finish call with the same enrollmentID
// fails with ErrAlreadyEnrolled.
func (s *Service) FinishEnrollment(ctx context.Context, userID models.ULID, enrollmentID, code string) ([]string, error) {
	if s.cfg == nil {
		return nil, errors.New("theauth: TOTP not configured")
	}
	raw, ok := s.enrollments.LoadAndDelete(enrollmentID)
	if !ok {
		return nil, models.NewError(models.CodeInvalidTOTP, "enrollment unknown or expired", nil)
	}
	enroll, ok := raw.(*enrollment)
	if !ok || enroll.userID != userID {
		return nil, models.NewError(models.CodeInvalidTOTP, "enrollment user mismatch", nil)
	}
	if time.Now().After(enroll.expiresAt) {
		return nil, models.NewError(models.CodeInvalidTOTP, "enrollment expired", nil)
	}
	if !totp.Validate(code, enroll.secret) {
		// Restore the entry so the user can retry within the window
		// without having to re-scan the QR. The 6-digit code rotates
		// every 30s; brute force is bounded by the TTL plus the
		// pending session counter (applied at verify time).
		enroll.expiresAt = time.Now().Add(enrollmentTTL)
		s.enrollments.Store(enrollmentID, enroll)
		return nil, models.NewError(models.CodeInvalidTOTP, "invalid code", nil)
	}
	// Confirm the persisted row. If it is already confirmed (race with a
	// second /finish call), surface ErrAlreadyEnrolled rather than minting
	// a second batch of recovery codes.
	if existing, err := s.storage.TOTPSecretByUserID(ctx, userID); err == nil && existing != nil && existing.ConfirmedAt != nil {
		return nil, models.NewError(models.CodeAlreadyEnrolled, "totp already enrolled", ErrAlreadyEnrolled)
	}
	now := time.Now()
	if err := s.storage.ConfirmTOTPSecret(ctx, userID, now); err != nil {
		return nil, fmt.Errorf("theauth: confirm totp: %w", err)
	}
	// Mint recovery codes. The plaintext list is returned to the caller
	// here and nowhere else; we persist only salted hashes.
	count := s.cfg.RecoveryCodeCount
	plain := make([]string, 0, count)
	stored := make([]models.RecoveryCode, 0, count)
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
		stored = append(stored, models.RecoveryCode{
			ID:        ulid.New(),
			UserID:    userID,
			CodeHash:  h,
			CreatedAt: now,
		})
	}
	if err := s.storage.InsertRecoveryCodes(ctx, stored); err != nil {
		return nil, fmt.Errorf("theauth: insert recovery codes: %w", err)
	}
	s.auditEm.EmitAudit(ctx, "totp.enrolled", models.TargetRef{Type: "user", ID: userID.String()}, nil)
	slog.Info("theauth: totp enrolled", "user_id", userID.String(), "recovery_codes", count)
	return plain, nil
}

// ErrAlreadyEnrolled is the sentinel returned when /auth/totp/enroll/finish
// is called against a user who already has a confirmed TOTP secret.
// Callers must DELETE /auth/totp first to re-enroll. Re-exported from root
// errors.go for compatibility.
var ErrAlreadyEnrolled = errors.New("theauth: totp already enrolled")

// IssuePending2FA mints a short-lived session whose AuthLevel is
// AuthLevelPending2FA. The cookie name is identical to the full session
// cookie so the browser sends it everywhere; middleware/RequireAuth
// rejects it except on the two TOTP verify endpoints (handled by the
// requirePendingOrFull tag in handlers_totp.go).
func (s *Service) IssuePending2FA(ctx context.Context, userID models.ULID, ua, ip string) (string, models.Session, error) {
	tok, err := crypto.NewToken()
	if err != nil {
		return "", models.Session{}, err
	}
	now := time.Now()
	sess := models.Session{
		ID:        ulid.New(),
		UserID:    userID,
		TokenHash: crypto.HashToken(tok),
		UserAgent: ua,
		IP:        ip,
		CreatedAt: now,
		// 10-minute TTL: matches the time a user can reasonably take to
		// pull their phone out, open the authenticator, and type the code.
		ExpiresAt: now.Add(10 * time.Minute),
		AuthLevel: models.AuthLevelPending2FA,
	}
	stored, err := s.storage.CreateSessionWithAuthLevel(ctx, sess)
	if err != nil {
		return "", models.Session{}, err
	}
	return tok, stored, nil
}

// Verify consumes a 6-digit code against the user's confirmed secret,
// upgrades their pending session to full, and returns the (same) token
// with the upgraded session row. On five consecutive failures the pending
// session is revoked.
func (s *Service) Verify(ctx context.Context, pendingSessionToken, code string) (string, models.Session, error) {
	sess, _, err := s.sessions.Validate(ctx, pendingSessionToken)
	if err != nil {
		return "", models.Session{}, err
	}
	if sess.AuthLevel != models.AuthLevelPending2FA {
		return "", models.Session{}, models.NewError(models.CodeInvalidCredentials, "session is not pending 2fa", nil)
	}
	secret, err := s.decryptSecret(ctx, sess.UserID)
	if err != nil {
		return "", models.Session{}, err
	}
	if !totp.Validate(code, secret) {
		s.recordPendingFailure(ctx, sess.ID, sess.UserID)
		return "", models.Session{}, models.NewError(models.CodeInvalidTOTP, "invalid code", nil)
	}
	s.clearPendingFailure(sess.ID)
	if err := s.storage.UpdateSessionAuthLevel(ctx, sess.ID, models.AuthLevelFull); err != nil {
		return "", models.Session{}, err
	}
	updated := *sess
	updated.AuthLevel = models.AuthLevelFull
	return pendingSessionToken, updated, nil
}

// ConsumeRecoveryCode upgrades a pending session by consuming one unused
// recovery code. Five failures revoke the session just like Verify.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, models.Session, error) {
	sess, _, err := s.sessions.Validate(ctx, pendingSessionToken)
	if err != nil {
		return "", models.Session{}, err
	}
	if sess.AuthLevel != models.AuthLevelPending2FA {
		return "", models.Session{}, models.NewError(models.CodeInvalidCredentials, "session is not pending 2fa", nil)
	}
	if err := s.storage.ConsumeRecoveryCode(ctx, sess.UserID, code, time.Now()); err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			s.recordPendingFailure(ctx, sess.ID, sess.UserID)
			return "", models.Session{}, models.NewError(models.CodeInvalidTOTP, "invalid recovery code", nil)
		}
		return "", models.Session{}, err
	}
	s.clearPendingFailure(sess.ID)
	if err := s.storage.UpdateSessionAuthLevel(ctx, sess.ID, models.AuthLevelFull); err != nil {
		return "", models.Session{}, err
	}
	updated := *sess
	updated.AuthLevel = models.AuthLevelFull
	return pendingSessionToken, updated, nil
}

// Delete removes a user's TOTP secret. Used by DELETE /auth/totp to
// turn off 2FA. Returns nil if the user had no secret; storage layer
// idempotency contract. Emits a totp.disabled audit on success.
func (s *Service) Delete(ctx context.Context, userID models.ULID) error {
	if err := s.storage.DeleteTOTPSecret(ctx, userID); err != nil {
		return err
	}
	s.auditEm.EmitAudit(ctx, "totp.disabled", models.TargetRef{Type: "user", ID: userID.String()}, nil)
	return nil
}

// decryptSecret loads the confirmed secret for a user and Decrypts it
// using the AES-GCM key from Config.EncryptionKey. Returns
// CodeInvalidCredentials when the user has no confirmed secret (defensive;
// this should not happen on a pending session, but a UI bug could deliver
// one).
func (s *Service) decryptSecret(ctx context.Context, userID models.ULID) (string, error) {
	row, err := s.storage.TOTPSecretByUserID(ctx, userID)
	if err != nil || row == nil || row.ConfirmedAt == nil {
		return "", models.NewError(models.CodeInvalidCredentials, "no totp credential", nil)
	}
	plain, err := crypto.Decrypt(s.encryptionKey, row.SecretEnc)
	if err != nil {
		return "", fmt.Errorf("theauth: decrypt totp: %w", err)
	}
	return string(plain), nil
}

// recordPendingFailure bumps the in-memory failure counter for the given
// pending session. On the pendingSessionMaxFailures'th failure the session
// is revoked (forcing a fresh password verify before another attempt).
func (s *Service) recordPendingFailure(ctx context.Context, sessID models.ULID, userID models.ULID) {
	raw, _ := s.pendingFailures.LoadOrStore(sessID, &failureCounter{})
	c, ok := raw.(*failureCounter)
	if !ok {
		return
	}
	c.mu.Lock()
	c.count++
	hit := c.count >= pendingSessionMaxFailures
	c.mu.Unlock()
	if hit {
		if err := s.storage.RevokeSession(ctx, sessID); err != nil {
			slog.Warn("theauth: revoke pending session after totp brute force",
				"err", err.Error(), "session_id", sessID.String(), "user_id", userID.String())
		}
		s.pendingFailures.Delete(sessID)
	}
}

// clearPendingFailure resets the counter on a successful verify.
func (s *Service) clearPendingFailure(sessID models.ULID) {
	s.pendingFailures.Delete(sessID)
}

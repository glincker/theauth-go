package password

import (
	"context"
	"crypto/sha1" //nolint:gosec // HIBP k-anonymity protocol mandates SHA-1
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/throttle"
)

// DefaultMaxPasswordBytes is the longest accepted password: bcrypt, still
// accepted for migrated hashes, silently ignores bytes past 72.
const DefaultMaxPasswordBytes = 72

// BreachChecker reports whether a password appears in a known breach corpus.
type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

// SignupGate decides whether a signup may proceed. Begin returns a done
// callback invoked once the attempt finishes, with the created user or nil.
type SignupGate interface {
	Begin(ctx context.Context) (done func(created *models.User), err error)
}

type ctxKey int

const signupMetaKey ctxKey = 1

// SignupMeta carries per-request signup inputs that are not part of the
// Signup signature.
type SignupMeta struct {
	SetupToken string
	IP         string
}

// WithSignupMeta attaches m to ctx for SignupGate implementations.
func WithSignupMeta(ctx context.Context, m SignupMeta) context.Context {
	return context.WithValue(ctx, signupMetaKey, m)
}

// SignupMetaFromContext returns the SignupMeta attached by WithSignupMeta.
func SignupMetaFromContext(ctx context.Context) SignupMeta {
	m, _ := ctx.Value(signupMetaKey).(SignupMeta)
	return m
}

// ValidatePassword applies the length policy and the optional breach check.
// A failing breach lookup is logged and ignored (fail open).
func (s *Service) ValidatePassword(ctx context.Context, pw string) error {
	minLen := s.cfg.MinLength
	if minLen <= 0 {
		minLen = MinPasswordLength
	}
	maxBytes := s.cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPasswordBytes
	}
	if len(pw) < minLen {
		return models.NewError(models.CodeWeakPassword, fmt.Sprintf("password must be at least %d characters", minLen), nil)
	}
	if len(pw) > maxBytes {
		return models.NewError(models.CodeWeakPassword, fmt.Sprintf("password must be at most %d bytes", maxBytes), nil)
	}
	if s.cfg.Breach == nil {
		return nil
	}
	breached, err := s.cfg.Breach.IsBreached(ctx, pw)
	if err != nil {
		slog.Warn("theauth: password breach check failed, allowing", "err", err.Error())
		return nil
	}
	if breached {
		return models.NewError(models.CodeWeakPassword, "password appears in a known data breach", nil)
	}
	return nil
}

// AdminSetPassword replaces a user's password without a reset token, revokes
// their sessions, and clears login and MFA lockouts. Intended for a
// recover-admin command run by someone with host access.
func (s *Service) AdminSetPassword(ctx context.Context, emailAddr, newPassword string) (models.ULID, error) {
	emailAddr = s.normalizeEmail(emailAddr)
	if err := s.ValidatePassword(ctx, newPassword); err != nil {
		return models.ULID{}, err
	}
	user, err := s.storage.UserByEmail(ctx, emailAddr)
	if errors.Is(err, models.ErrStorageNotFound) {
		return models.ULID{}, models.ErrStorageNotFound
	}
	if err != nil {
		return models.ULID{}, fmt.Errorf("theauth: admin password reset lookup: %w", err)
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return models.ULID{}, fmt.Errorf("theauth: admin password reset hash: %w", err)
	}
	if err := s.storage.SetUserPassword(ctx, user.ID, hash); err != nil {
		return models.ULID{}, fmt.Errorf("theauth: admin password reset store: %w", err)
	}
	if err := s.storage.RevokeUserSessions(ctx, user.ID); err != nil {
		slog.Warn("theauth: revoke sessions after admin password reset failed", "user_id", user.ID.String(), "err", err.Error())
	}
	if s.cfg.Throttle != nil {
		if err := s.cfg.Throttle.UnlockIdentifier(ctx, emailAddr, user.ID.String()); err != nil {
			slog.Warn("theauth: clear lockout after admin password reset failed", "user_id", user.ID.String(), "err", err.Error())
		}
		if err := s.cfg.Throttle.ClearLoginBackoff(ctx, emailAddr); err != nil {
			slog.Warn("theauth: clear login backoff after admin password reset failed", "user_id", user.ID.String(), "err", err.Error())
		}
	}
	s.auditEm.EmitAudit(ctx, "password.admin_reset", models.TargetRef{Type: "user", ID: user.ID.String()}, nil)
	return user.ID, nil
}

func (s *Service) checkThrottle(ctx context.Context, ip, ident string) error {
	if s.cfg.Throttle == nil {
		return nil
	}
	err := s.cfg.Throttle.CheckLogin(ctx, ip, ident)
	if err == nil {
		return nil
	}
	return ThrottleError(err)
}

func (s *Service) recordFailure(ctx context.Context, ip, ident string) {
	if s.cfg.Throttle == nil {
		return
	}
	if err := s.cfg.Throttle.RecordLoginFailure(ctx, ip, ident); err != nil {
		slog.Warn("theauth: record login failure", "err", err.Error())
	}
}

func (s *Service) recordSuccess(ctx context.Context, ip, ident string) {
	if s.cfg.Throttle == nil {
		return
	}
	if err := s.cfg.Throttle.RecordLoginSuccess(ctx, ip, ident); err != nil {
		slog.Warn("theauth: clear login throttle", "err", err.Error())
	}
}

// ThrottleError converts a throttle refusal into the public error shape.
// Non-refusal errors are wrapped and surface as internal errors.
func ThrottleError(err error) error {
	var be *throttle.BlockedError
	if errors.As(err, &be) {
		if be.Locked {
			e := models.NewError(models.CodeAccountLocked, "too many failed attempts, try again later", nil)
			e.RetryAfter = be.RetryAfter
			return e
		}
		e := models.NewError(models.CodeRateLimited, "too many attempts, try again later", nil)
		e.RetryAfter = be.RetryAfter
		return e
	}
	return fmt.Errorf("theauth: throttle: %w", err)
}

// HIBPChecker queries the Have I Been Pwned range API using k-anonymity:
// only the first five hex characters of the SHA-1 hash leave the process.
type HIBPChecker struct {
	// BaseURL defaults to https://api.pwnedpasswords.com/range/.
	BaseURL string
	// Client defaults to an http.Client with a 3 second timeout.
	Client *http.Client
	// MinCount flags a password only when it was seen at least this many
	// times; zero means once.
	MinCount int
}

// IsBreached implements BreachChecker.
func (h *HIBPChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // HIBP protocol, not used for security of the secret
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]
	base := h.BaseURL
	if base == "" {
		base = "https://api.pwnedpasswords.com/range/"
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("theauth: hibp request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("theauth: hibp lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("theauth: hibp lookup: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return false, fmt.Errorf("theauth: hibp read: %w", err)
	}
	min := h.MinCount
	if min <= 0 {
		min = 1
	}
	for _, line := range strings.Split(string(body), "\n") {
		hashPart, countPart, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !strings.EqualFold(hashPart, suffix) {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(countPart, "%d", &n); err != nil {
			return false, fmt.Errorf("theauth: hibp parse count: %w", err)
		}
		return n >= min, nil
	}
	return false, nil
}

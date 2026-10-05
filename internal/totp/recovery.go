package totp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// ErrRecoveryUnsupported is returned when the storage adapter lacks the
// RecoveryStore capability.
var ErrRecoveryUnsupported = errors.New("theauth: storage does not support recovery code management")

// ErrNotEnrolled is returned when the user has no confirmed TOTP secret.
var ErrNotEnrolled = errors.New("theauth: totp not enrolled")

// RecoveryStore is the optional storage capability behind Status and
// RegenerateRecoveryCodes.
type RecoveryStore interface {
	CountUnusedRecoveryCodes(ctx context.Context, userID models.ULID) (int, error)
	ReplaceRecoveryCodes(ctx context.Context, userID models.ULID, codes []models.RecoveryCode) error
}

// Status is the TOTP state shown on a security settings page.
type Status struct {
	Enrolled bool `json:"enrolled"`
	// RecoveryCodesRemaining is -1 when the storage cannot count them.
	RecoveryCodesRemaining int `json:"recoveryCodesRemaining"`
}

// SetRecoveryStore installs the optional recovery capability.
func (s *Service) SetRecoveryStore(r RecoveryStore) { s.recovery = r }

// Status reports whether the user has a confirmed secret and how many
// recovery codes remain unused.
func (s *Service) Status(ctx context.Context, userID models.ULID) (Status, error) {
	if s.cfg == nil {
		return Status{}, errors.New("theauth: TOTP not configured")
	}
	row, err := s.storage.TOTPSecretByUserID(ctx, userID)
	if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
		return Status{}, fmt.Errorf("theauth: load totp: %w", err)
	}
	st := Status{RecoveryCodesRemaining: -1}
	if row == nil || row.ConfirmedAt == nil {
		st.RecoveryCodesRemaining = 0
		return st, nil
	}
	st.Enrolled = true
	if s.recovery != nil {
		n, err := s.recovery.CountUnusedRecoveryCodes(ctx, userID)
		if err != nil {
			return Status{}, fmt.Errorf("theauth: count recovery codes: %w", err)
		}
		st.RecoveryCodesRemaining = n
	}
	return st, nil
}

// RegenerateRecoveryCodes replaces every recovery code of an enrolled user
// with a fresh batch and returns the plaintext codes once.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID models.ULID) ([]string, error) {
	if s.cfg == nil {
		return nil, errors.New("theauth: TOTP not configured")
	}
	if s.recovery == nil {
		return nil, ErrRecoveryUnsupported
	}
	row, err := s.storage.TOTPSecretByUserID(ctx, userID)
	if err != nil || row == nil || row.ConfirmedAt == nil {
		return nil, ErrNotEnrolled
	}
	count := s.cfg.RecoveryCodeCount
	if count <= 0 {
		count = 10
	}
	now := time.Now()
	plain := make([]string, 0, count)
	stored := make([]models.RecoveryCode, 0, count)
	for range count {
		c, err := crypto.GenerateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("theauth: generate recovery code: %w", err)
		}
		h, err := crypto.HashRecoveryCode(c)
		if err != nil {
			return nil, fmt.Errorf("theauth: hash recovery code: %w", err)
		}
		plain = append(plain, c)
		stored = append(stored, models.RecoveryCode{ID: ulid.New(), UserID: userID, CodeHash: h, CreatedAt: now})
	}
	if err := s.recovery.ReplaceRecoveryCodes(ctx, userID, stored); err != nil {
		return nil, fmt.Errorf("theauth: replace recovery codes: %w", err)
	}
	s.auditEm.EmitAudit(ctx, "totp.recovery_regenerated", models.TargetRef{Type: "user", ID: userID.String()}, nil)
	slog.Info("theauth: recovery codes regenerated", "user_id", userID.String())
	return plain, nil
}

func (s *Service) emitMFA(ctx context.Context, userID models.ULID, method string, ok bool) {
	action := "mfa.failed"
	if ok {
		action = "mfa.verified"
	}
	s.auditEm.EmitAudit(ctx, action, models.TargetRef{Type: "user", ID: userID.String()}, map[string]any{"method": method})
}

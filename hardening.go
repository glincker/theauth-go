package theauth

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/internal/emailnorm"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/throttle"
)

// LoginThrottleStore persists login and MFA throttle counters. The default
// is an in-memory store; supply your own to share state across processes.
type LoginThrottleStore = throttle.Store

// LoginThrottleEntry is one record held by a LoginThrottleStore.
type LoginThrottleEntry = throttle.Entry

// LoginThrottleCASStore is the optional LoginThrottleStore capability that
// lets several processes share counters without losing updates.
type LoginThrottleCASStore = throttle.CASStore

// BreachChecker reports whether a password appears in a known breach corpus.
type BreachChecker = password.BreachChecker

// HIBPBreachChecker is a BreachChecker backed by the Have I Been Pwned
// k-anonymity range API.
type HIBPBreachChecker = password.HIBPChecker

// NewMemoryLoginThrottleStore returns the default in-memory store, capped at
// maxEntries (zero selects 100000). Expired entries are swept on writes.
func NewMemoryLoginThrottleStore(maxEntries int) LoginThrottleStore {
	return throttle.NewMemoryStore(maxEntries)
}

// LoginThrottleConfig tunes login backoff, per-user lockout and MFA attempt
// limits. The nil Config.LoginThrottle selects the defaults below; set
// Disabled to turn the feature off.
type LoginThrottleConfig struct {
	Disabled bool
	// Store defaults to an in-memory store.
	Store LoginThrottleStore
	// GraceFailures is how many failed logins per (IP, identifier) pass
	// before backoff starts. Default 3.
	GraceFailures int
	// BaseDelay is the first backoff delay, doubled per further failure. Default 1s.
	BaseDelay time.Duration
	// MaxDelay caps the backoff. Default 15m.
	MaxDelay time.Duration
	// ResetAfter forgets failure counts after this much idle time. Default 15m.
	ResetAfter time.Duration
	// UserMaxFailures consecutive failures against one identifier, from any
	// IP, trigger a lockout. Default 10.
	UserMaxFailures int
	// UserLockout is how long that lockout lasts before auto-expiring. Default 15m.
	UserLockout time.Duration
	// MFAMaxFailures wrong TOTP or recovery codes per user, across all
	// pending sessions, trigger an MFA lockout. Default 5.
	MFAMaxFailures int
	// MFALockout is how long the MFA lockout lasts. Default 15m.
	MFALockout time.Duration
	// MaxEntries caps the default in-memory store. Default 100000.
	MaxEntries int
}

func (c *LoginThrottleConfig) limiter() *throttle.Limiter {
	if c == nil {
		return throttle.New(nil, throttle.Config{})
	}
	if c.Disabled {
		return nil
	}
	store := c.Store
	if store == nil {
		store = throttle.NewMemoryStore(c.MaxEntries)
	}
	return throttle.New(store, throttle.Config{
		GraceFailures:   c.GraceFailures,
		BaseDelay:       c.BaseDelay,
		MaxDelay:        c.MaxDelay,
		ResetAfter:      c.ResetAfter,
		UserMaxFailures: c.UserMaxFailures,
		UserLockout:     c.UserLockout,
		MFAMaxFailures:  c.MFAMaxFailures,
		MFALockout:      c.MFALockout,
	})
}

func (a *TheAuth) normalizeEmail(raw string) string { return a.emailNorm.Normalize(raw) }

func newEmailNormalizer(nfkc bool) emailnorm.Normalizer { return emailnorm.Normalizer{NFKC: nfkc} }

// NormalizeEmail returns the canonical form this instance uses for every
// email lookup: trimmed, lowercased, and NFKC-folded when Config.EmailNFKC is set.
func (a *TheAuth) NormalizeEmail(raw string) string { return a.normalizeEmail(raw) }

// ResetPasswordAdmin sets a new password for the user with the given email
// without a reset token, revokes their sessions and clears login and MFA
// lockouts. It enforces the configured password policy and is meant for a
// recover-admin command run by someone with host access.
func (a *TheAuth) ResetPasswordAdmin(ctx context.Context, emailAddr, newPassword string) error {
	userID, err := a.passwordSvc.AdminSetPassword(ctx, emailAddr, newPassword)
	if err != nil {
		return err
	}
	if user, uerr := a.storage.UserByID(ctx, userID); uerr == nil {
		a.fireOnPasswordChange(ctx, user)
	}
	return nil
}

// UnlockUser clears the login lockout and MFA lockout for the user with the
// given email so they can try again immediately.
func (a *TheAuth) UnlockUser(ctx context.Context, emailAddr string) error {
	if a.throttle == nil {
		return nil
	}
	canon := a.normalizeEmail(emailAddr)
	user, err := a.storage.UserByEmail(ctx, canon)
	userID := ""
	if err == nil && user != nil {
		userID = user.ID.String()
	}
	if err := a.throttle.UnlockIdentifier(ctx, canon, userID); err != nil {
		return fmt.Errorf("theauth: unlock user: %w", err)
	}
	return nil
}

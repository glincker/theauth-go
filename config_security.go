package theauth

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/bootstrap"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/throttle"
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

// BootstrapConfig closes public signup and gates creation of the first user
// behind a one-time setup token. The storage must implement UserCountStorage.
//
// While no user exists, password signup requires the token in the
// X-Setup-Token header or a "setupToken" body field. After the first user
// exists, signup is refused with CodeSignupClosed unless
// OpenSignupAfterFirstUser is set. Magic-link account creation follows the
// same rule but can never present a token, so the first admin must sign up
// with a password. Granting the new user an admin role is left to OnFirstUser.
type BootstrapConfig = bootstrap.Config

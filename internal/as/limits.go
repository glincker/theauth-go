package as

import (
	"context"
	"runtime"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

const (
	DefaultPerIPPerMinute     = 120
	DefaultPerClientPerMinute = 300
	DefaultSecretVerifyWait   = 2 * time.Second
	maxDefaultSecretVerifies  = 8
)

// RateLimits tunes the per-client and per-IP limits on the token, revoke, introspect, PAR and
// bc-authorize endpoints. A zero field takes the default; a negative field disables that control.
type RateLimits struct {
	// PerIPPerMinute caps requests per client IP across the limited endpoints (default 120).
	PerIPPerMinute int

	// PerClientPerMinute caps requests presenting a client_id and secret, per client. It slows secret
	// guessing from many IPs. Requests without a secret are not counted, so an attacker cannot lock a
	// public client out by naming it (default 300).
	PerClientPerMinute int

	// MaxConcurrentSecretVerifications caps Argon2id verifications running at once. Excess requests wait up to
	// SecretVerifyWait, then get 503 (default min(8, max(2, GOMAXPROCS))).
	MaxConcurrentSecretVerifications int

	// SecretVerifyWait is how long a request waits for a verification slot (default 2s).
	SecretVerifyWait time.Duration
}

func applyRateLimitDefaults(c *Config) {
	if c.RateLimits == nil {
		c.RateLimits = &RateLimits{}
	}
	r := c.RateLimits
	if r.PerIPPerMinute == 0 {
		r.PerIPPerMinute = DefaultPerIPPerMinute
	}
	if r.PerClientPerMinute == 0 {
		r.PerClientPerMinute = DefaultPerClientPerMinute
	}
	if r.MaxConcurrentSecretVerifications == 0 {
		n := runtime.GOMAXPROCS(0)
		if n < 2 {
			n = 2
		}
		if n > maxDefaultSecretVerifies {
			n = maxDefaultSecretVerifies
		}
		r.MaxConcurrentSecretVerifications = n
	}
	if r.SecretVerifyWait <= 0 {
		r.SecretVerifyWait = DefaultSecretVerifyWait
	}
}

func (s *Service) verifyClientSecret(ctx context.Context, secret, phc string) (bool, error) {
	if s.verifySem != nil {
		wait := time.NewTimer(s.Cfg.RateLimits.SecretVerifyWait)
		defer wait.Stop()
		select {
		case s.verifySem <- struct{}{}:
			defer func() { <-s.verifySem }()
		case <-wait.C:
			return false, models.ErrOAuthServerBusy
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return crypto.VerifyPassword(secret, phc)
}

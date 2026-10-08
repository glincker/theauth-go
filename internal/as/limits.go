package as

import (
	"context"
	"runtime"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// limits.go: abuse controls for the AS HTTP endpoints. The request limits
// themselves are applied by the handler middleware (internal/as/handlers);
// this file holds their configuration and the concurrency cap on Argon2id
// client-secret verification, which is the expensive step an attacker would
// otherwise use to burn CPU and memory (each verify allocates 64 MiB).

// Defaults for RateLimits. Negative config values disable a control.
const (
	DefaultPerIPPerMinute     = 120
	DefaultPerClientPerMinute = 300
	DefaultSecretVerifyWait   = 2 * time.Second
	maxDefaultSecretVerifies  = 8
)

// RateLimits tunes /oauth/token, /oauth/revoke, /oauth/introspect, /oauth/par
// and /oauth/bc-authorize. A zero field takes the default; a negative field
// turns that control off.
type RateLimits struct {
	// PerIPPerMinute caps requests per client IP per minute across the
	// limited endpoints (one shared budget per IP). Default 120.
	PerIPPerMinute int

	// PerClientPerMinute caps requests that present a client_id and a client
	// secret, per client_id per minute. It slows secret guessing against one
	// client from many IPs. Requests without a secret (public clients,
	// refresh and code grants) are not counted, so an attacker cannot lock a
	// public client out by naming it. Default 300.
	PerClientPerMinute int

	// MaxConcurrentSecretVerifications caps Argon2id verifications running
	// at once. Excess requests wait up to SecretVerifyWait, then get 503
	// temporarily_unavailable. Default min(8, max(2, GOMAXPROCS)).
	MaxConcurrentSecretVerifications int

	// SecretVerifyWait is how long a request waits for a verification slot.
	// Default 2s.
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

// verifyClientSecret runs the Argon2id check behind the concurrency cap.
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

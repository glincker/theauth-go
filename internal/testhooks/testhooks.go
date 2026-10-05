// Package testhooks lets black-box tests reach unexported root behavior
// without widening the public API. The root package registers the hooks in
// an init function; the receiver is typed any because this package cannot
// import the root.
package testhooks

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Limiter is the handle over the root keyed rate limiter.
type Limiter interface {
	Allow(key string) bool
	Stop()
	EntryCount() int
}

// Hooks registered by the root package.
var (
	ValidateEmail        func(raw string) (string, error)
	IssueSession         func(a any, ctx context.Context, user models.User, ua, ip string) (string, models.Session, error)
	ValidateSession      func(a any, ctx context.Context, token string) (*models.Session, *models.User, error)
	RequestMagicLink     func(a any, ctx context.Context, email string) (string, error)
	ConsumeMagicLink     func(a any, ctx context.Context, token string) (string, *models.User, error)
	SetBaseURL           func(a any, url string)
	SignupWithPassword   func(a any, ctx context.Context, email, password string) (*models.User, string, error)
	SigninWithPassword   func(a any, ctx context.Context, email, password, ua, ip string) (string, *models.User, error)
	RequestPasswordReset func(a any, ctx context.Context, email string) (string, error)
	ResetPassword        func(a any, ctx context.Context, token, newPassword string) error
	NewKeyedLimiter      func(perMinute int, evictAfter, tick time.Duration) Limiter
	LinkOAuth            func(a any, ctx context.Context, sessionToken, provider, providerUserID string) error
	LinkPassword         func(a any, ctx context.Context, sessionToken, password string) error
	MergeAccounts        func(a any, ctx context.Context, sessionToken string, secondaryID models.ULID) error
	UnlinkOAuth          func(a any, ctx context.Context, sessionToken, provider string) error
	SetAPITokenClock     func(a any, now func() time.Time)
)

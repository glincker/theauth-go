package apitokens

import (
	"context"
	"net/http"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/revocation"
)

// Host is what the service needs from the root TheAuth instance.
type Host interface {
	CookieName() string
	PathPrefix() string
	ValidateSession(ctx context.Context, token string) (*Session, *User, error)
	PublishRevocation(ctx context.Context, ev revocation.Event)
	RecordTokenMinted(ctx context.Context, userID ULID, kind string)
	RecordTokenRevoked(ctx context.Context, userID ULID, kind string)
	EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any)
	ClientIP(r *http.Request) string
	RequireAuth() func(http.Handler) http.Handler
	RateLimitByIP(perMinute int) func(http.Handler) http.Handler
	UserFromContext(ctx context.Context) (*User, bool)
	WithUser(ctx context.Context, u *User) context.Context
}

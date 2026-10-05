package theauth

import (
	"context"
	"time"

	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
)

// OAuthState is the per-flow record kept between /start and /callback.
type OAuthState = internaloauth.State

// OAuthStateStore holds OAuth flow state between /start and /callback.
// Implement it over a shared store (Redis, SQL) to run several replicas
// behind a load balancer; the default in-memory store is single-process.
type OAuthStateStore = internaloauth.StateStore

// NewMemoryOAuthStateStore returns the default in-process OAuthStateStore.
// It sweeps expired entries in the background; call Close when done.
func NewMemoryOAuthStateStore() *internaloauth.MemoryStateStore {
	return internaloauth.NewMemoryStateStore()
}

// OAuthSignupPolicy decides whether an OAuth sign-in may create a new user.
type OAuthSignupPolicy string

const (
	// OAuthSignupOpen lets any provider-authenticated identity create an
	// account. It is the default so existing v2 deployments are unchanged.
	OAuthSignupOpen OAuthSignupPolicy = "open"
	// OAuthSignupClosed refuses to create users from OAuth; only existing
	// users and linked accounts can sign in.
	OAuthSignupClosed OAuthSignupPolicy = "closed"
	// OAuthSignupAllowedDomains creates users only when the provider-verified
	// email domain is listed in OAuthConfig.AllowedEmailDomains.
	OAuthSignupAllowedDomains OAuthSignupPolicy = "allowed_domains"
	// OAuthSignupInvite creates users only when OAuthConfig.InviteCheck
	// approves the verified email.
	OAuthSignupInvite OAuthSignupPolicy = "invite"
)

// OAuthConfig tunes OAuth login hardening. The zero value keeps v2
// behavior: in-memory state with a 10 minute TTL, no return-to parameter,
// and open signup.
type OAuthConfig struct {
	// StateStore overrides the default in-memory state store.
	StateStore OAuthStateStore
	// StateTTL bounds how long a flow may take. Defaults to 10 minutes.
	StateTTL time.Duration
	// AllowedReturnTo lists the post-login destinations a caller may request
	// with ?return_to=. Entries are exact absolute URLs or paths beginning
	// with "/" (matched as exact path, or prefix when ending in "*").
	// Anything else is ignored and Config.PostLoginRedirect is used.
	AllowedReturnTo []string
	// Signup selects the new-user policy. Defaults to OAuthSignupOpen.
	Signup OAuthSignupPolicy
	// AllowedEmailDomains is required for OAuthSignupAllowedDomains.
	AllowedEmailDomains []string
	// InviteCheck is required for OAuthSignupInvite. It receives the
	// provider-verified, lower-cased email.
	InviteCheck func(ctx context.Context, email string) (bool, error)
}

func oauthConfigFromRoot(c *OAuthConfig, prefix string) internaloauth.Config {
	if c == nil {
		return internaloauth.Config{PathPrefix: prefix}
	}
	return internaloauth.Config{
		PathPrefix:          prefix,
		StateStore:          c.StateStore,
		StateTTL:            c.StateTTL,
		AllowedReturnTo:     append([]string(nil), c.AllowedReturnTo...),
		Signup:              string(c.Signup),
		AllowedEmailDomains: append([]string(nil), c.AllowedEmailDomains...),
		InviteCheck:         c.InviteCheck,
	}
}

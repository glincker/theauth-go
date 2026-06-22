package theauth

import (
	"context"
	"net/http"
	"time"

	accounthandlers "github.com/glincker/theauth-go/internal/account"
	"github.com/glincker/theauth-go/internal/identitylink"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// handlers_account.go: thin forwarder around the extracted
// internal/account/handlers package. PR F architecture reorg
// (2026-06-20) moved the six /account/* end-user self-service
// endpoints there; this file keeps the mountAccount entrypoint and
// the two small adapters that bridge the *TheAuth surface to the
// handler-side service interfaces.

// accountAgentAdapter implements accounthandlers.AgentService on top
// of root *TheAuth. AgentByID forwards to the agentSvc field directly
// because the public *TheAuth surface does not expose an AgentByID
// method (only the wider GetAgent, which the handler uses on the
// admin path).
type accountAgentAdapter struct{ a *TheAuth }

func (s accountAgentAdapter) ListAgentsByOwner(ctx context.Context, owner models.AgentOwner) ([]models.Agent, error) {
	return s.a.ListAgentsByOwner(ctx, owner)
}

func (s accountAgentAdapter) CreateAgent(ctx context.Context, in models.CreateAgentInput) (models.Agent, models.AgentSecret, error) {
	return s.a.CreateAgent(ctx, in)
}

func (s accountAgentAdapter) AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error) {
	return s.a.agentSvc.AgentByID(ctx, id)
}

func (s accountAgentAdapter) RevokeAgent(ctx context.Context, agentID models.ULID, reason string) error {
	return s.a.RevokeAgent(ctx, agentID, reason)
}

// accountDelegationAdapter implements
// accounthandlers.DelegationService on top of root *TheAuth.
type accountDelegationAdapter struct{ a *TheAuth }

func (s accountDelegationAdapter) ListDelegationsForUser(ctx context.Context, userID models.ULID) ([]models.DelegationGrant, error) {
	return s.a.ListDelegationsForUser(ctx, userID)
}

func (s accountDelegationAdapter) GrantDelegation(ctx context.Context, in models.GrantDelegationInput) (models.DelegationGrant, error) {
	return s.a.GrantDelegation(ctx, in)
}

func (s accountDelegationAdapter) GrantByID(ctx context.Context, grantID models.ULID) (*models.DelegationGrant, error) {
	return s.a.delegationSvc.GrantByID(ctx, grantID)
}

func (s accountDelegationAdapter) RevokeDelegation(ctx context.Context, grantID models.ULID, reason string) error {
	return s.a.RevokeDelegation(ctx, grantID, reason)
}

// accountIdentityLinkAdapter wraps *TheAuth to satisfy the
// accounthandlers.IdentityLinkService interface without importing root from
// an internal package.
type accountIdentityLinkAdapter struct{ a *TheAuth }

func (s accountIdentityLinkAdapter) LinkOAuthToCurrentUser(
	ctx context.Context,
	sessionToken, providerName, providerUserID string,
	accessTokenEnc, refreshTokenEnc []byte,
	expiresAt *time.Time,
	scope string,
) error {
	return s.a.identityLinkSvc.LinkOAuthToCurrentUser(
		ctx, sessionToken, providerName, providerUserID,
		accessTokenEnc, refreshTokenEnc, expiresAt, scope,
	)
}

func (s accountIdentityLinkAdapter) LinkPasswordToCurrentUser(ctx context.Context, sessionToken, password string) error {
	return s.a.identityLinkSvc.LinkPasswordToCurrentUser(ctx, sessionToken, password)
}

func (s accountIdentityLinkAdapter) MergeAccounts(ctx context.Context, sessionToken string, secondaryID models.ULID, input identitylink.MergeInput) error {
	return s.a.identityLinkSvc.MergeAccounts(ctx, sessionToken, secondaryID, input)
}

func (s accountIdentityLinkAdapter) UnlinkOAuthProvider(ctx context.Context, sessionToken, provider string) error {
	return s.a.identityLinkSvc.UnlinkOAuthProvider(ctx, sessionToken, provider)
}

// sessionTokenFromRequest extracts the raw session token from the request
// cookie. Passed to the identity-link handler so it can call the service
// methods with the caller's session token.
func (a *TheAuth) sessionTokenFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// mountAccount wires the /account routes via the extracted
// internal/account/handlers package. Idempotent guard matches the
// legacy root: only fires when AccountUX, AgentIdentity, and the AS
// are all configured.
//
// Identity-linking routes (/account/identities/*) are also mounted here
// whenever identityLinkSvc is non-nil (always true after wireServices).
func (a *TheAuth) mountAccount(r chi.Router) {
	if !a.accountUX || a.agentCfg == nil || a.as == nil {
		// Still mount identity-linking routes independently of AccountUX if
		// the service was constructed (which it always is after New).
		if a.identityLinkSvc != nil {
			h := accounthandlers.New(nil, nil, userFromRequest)
			h.WithIdentityLink(
				accountIdentityLinkAdapter{a: a},
				a.sessionTokenFromRequest,
				nil, // OAuthLinkInitiator wired below when providers are configured
			)
			h.Mount(r, a.RequireAuth())
		}
		return
	}
	h := accounthandlers.New(
		accountAgentAdapter{a: a},
		accountDelegationAdapter{a: a},
		userFromRequest,
	)
	if a.identityLinkSvc != nil {
		h.WithIdentityLink(
			accountIdentityLinkAdapter{a: a},
			a.sessionTokenFromRequest,
			nil, // OAuthLinkInitiator: wired when a separate PR adds OAuth link flow support
		)
	}
	h.Mount(r, a.RequireAuth())
}

package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/glincker/theauth-go/v2/internal/delegation"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// ErrIdentityDisabled is returned when RegisterAgent runs without Config.AgentIdentity.
var ErrIdentityDisabled = errors.New("theauth: agent identity is not enabled in Config")

// RegisterInput describes an agent or MCP client to register under a human.
type RegisterInput struct {
	OwnerID     models.ULID
	Name        string
	Description string
	// Scope is the set of scopes the agent may ever act with.
	Scope []string
	// Resource, when set, also records a delegation grant from the owner to
	// the agent for Scope on that resource.
	Resource string
	// MaxDuration bounds a delegated token's life under the grant. Defaults to
	// the configured DefaultDelegatedTokenTTL.
	MaxDuration time.Duration
	// GrantExpiresAt optionally ends the grant.
	GrantExpiresAt *time.Time
}

// Registration is the result of Register. Secret is shown once.
type Registration struct {
	Agent  models.Agent
	Secret models.AgentSecret
	Grant  *models.DelegationGrant
}

// Register creates an agent owned by a user and, when Resource is set, the
// delegation grant that lets it exchange tokens for that user.
func Register(ctx context.Context, svc *Service, dsvc *delegation.Service, defaultTTL time.Duration, in RegisterInput) (Registration, error) {
	if svc == nil || dsvc == nil {
		return Registration{}, ErrIdentityDisabled
	}
	owner := in.OwnerID
	ag, secret, err := svc.CreateAgent(ctx, models.CreateAgentInput{
		Owner: models.AgentOwner{UserID: &owner}, Name: in.Name, Description: in.Description, Scope: slices.Clone(in.Scope),
	})
	if err != nil {
		return Registration{}, fmt.Errorf("theauth: register agent: %w", err)
	}
	reg := Registration{Agent: ag, Secret: secret}
	if in.Resource == "" {
		return reg, nil
	}
	dur := in.MaxDuration
	if dur <= 0 {
		dur = defaultTTL
	}
	if dur <= 0 {
		dur = 15 * time.Minute
	}
	g, err := dsvc.GrantDelegation(ctx, models.GrantDelegationInput{
		UserID: in.OwnerID, AgentID: ag.ID, Scope: in.Scope, Resource: in.Resource,
		MaxDurationSeconds: int(dur.Seconds()), ExpiresAt: in.GrantExpiresAt,
	})
	if err != nil {
		return reg, fmt.Errorf("theauth: grant delegation for registered agent %s: %w", ag.ID, err)
	}
	reg.Grant = &g
	return reg, nil
}

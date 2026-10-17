package tokenvault

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	"github.com/oklog/ulid/v2"
)

// Resource returns the delegation resource string that authorizes an agent to
// use a provider's vault credential: "vault:<provider>".
func Resource(provider string) string { return "vault:" + provider }

// Delegations decides whether a user has delegated a provider scope set to an
// agent right now. Return false, nil for any non-grant; return an error only
// for a lookup failure (the vault fails closed on it).
type Delegations interface {
	Allows(ctx context.Context, userID, agentID, provider string, scopes []string, now time.Time) (bool, error)
}

// DelegationsFunc adapts a function to Delegations.
type DelegationsFunc func(ctx context.Context, userID, agentID, provider string, scopes []string, now time.Time) (bool, error)

// Allows implements Delegations.
func (f DelegationsFunc) Allows(ctx context.Context, userID, agentID, provider string, scopes []string, now time.Time) (bool, error) {
	return f(ctx, userID, agentID, provider, scopes, now)
}

// GrantReader is the slice of the OAuth server storage that GrantDelegations needs.
type GrantReader interface {
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error)
}

// GrantDelegations authorizes through the existing delegation grants. A grant
// for resource "vault:<provider>" with a scope list covering the request,
// neither revoked nor expired, allows the call. User and agent ids must be ULIDs.
type GrantDelegations struct{ Store GrantReader }

// Allows implements Delegations.
func (g GrantDelegations) Allows(ctx context.Context, userID, agentID, provider string, scopes []string, now time.Time) (bool, error) {
	uid, err := ulid.Parse(userID)
	if err != nil {
		return false, nil
	}
	aid, err := ulid.Parse(agentID)
	if err != nil {
		return false, nil
	}
	grant, err := g.Store.DelegationGrantByUserAgentResource(ctx, uid, aid, Resource(provider))
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if grant.RevokedAt != nil || (grant.ExpiresAt != nil && !grant.ExpiresAt.After(now)) {
		return false, nil
	}
	return subset(scopes, grant.Scope), nil
}

func subset(sub, sup []string) bool {
	set := make(map[string]struct{}, len(sup))
	for _, s := range sup {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

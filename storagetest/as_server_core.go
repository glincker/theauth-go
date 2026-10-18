package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// ASCoreStorage is the part of theauth.OAuthServerStorage that RunOAuthServerCore
// exercises: OAuth clients, authorization codes, refresh tokens and JWKS keys.
// It lets a backend that has not implemented agents and delegations yet run the
// authorization server contract for everything else.
type ASCoreStorage interface {
	InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error
	InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error)
	InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error
	InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error
}

// RunOAuthServerCore runs the client, authorization code, refresh token and
// JWKS key contract tests (the same ones RunOAuthServer runs) without the agent
// and delegation tests. Optional capabilities (code replay revocation, the
// access token denylist) are exercised when the store implements them.
func RunOAuthServerCore(t *testing.T, store ASCoreStorage) {
	t.Helper()
	full := adaptCore(store)
	t.Run("OAuthClients", func(t *testing.T) { testOAuthClients(t, full) })
	t.Run("AuthorizationCodes", func(t *testing.T) { testAuthorizationCodes(t, full) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, full) })
	t.Run("JWKSKeys", func(t *testing.T) { testJWKSKeys(t, full) })
}

var errNotInCoreSuite = errors.New("storagetest: agents and delegations are outside the AS core suite")

// coreOnlyOAuth adapts an ASCoreStorage to theauth.OAuthServerStorage. The
// optional capability probes in the shared tests type-assert the store they are
// given, so the wrappers below expose code replay revocation and the access
// token denylist only when the wrapped store has them.
type coreOnlyOAuth struct{ ASCoreStorage }

type replayRevoker interface {
	RevokeRefreshTokensByAuthCode(ctx context.Context, codeHash, reason string) ([]string, error)
}

type tokenDenier interface {
	DenyAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsAccessTokenDenied(ctx context.Context, jti string) (bool, error)
}

type coreWithReplay struct {
	coreOnlyOAuth
	replayRevoker
}

type coreWithDeny struct {
	coreOnlyOAuth
	tokenDenier
}

type coreWithReplayAndDeny struct {
	coreOnlyOAuth
	replayRevoker
	tokenDenier
}

func adaptCore(store ASCoreStorage) theauth.OAuthServerStorage {
	base := coreOnlyOAuth{store}
	r, hasReplay := store.(replayRevoker)
	d, hasDeny := store.(tokenDenier)
	switch {
	case hasReplay && hasDeny:
		return coreWithReplayAndDeny{base, r, d}
	case hasReplay:
		return coreWithReplay{base, r}
	case hasDeny:
		return coreWithDeny{base, d}
	}
	return base
}

func (coreOnlyOAuth) InsertAgent(context.Context, theauth.Agent) (theauth.Agent, error) {
	return theauth.Agent{}, errNotInCoreSuite
}

func (coreOnlyOAuth) AgentByID(context.Context, theauth.ULID) (*theauth.Agent, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) AgentByClientID(context.Context, string) (*theauth.Agent, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) AgentsByOwner(context.Context, theauth.AgentOwner) ([]theauth.Agent, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) UpdateAgentStatus(context.Context, theauth.ULID, string, time.Time) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) UpdateAgentExpiry(context.Context, theauth.ULID, *time.Time) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) UpdateAgentLastActive(context.Context, theauth.ULID, time.Time) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) InsertAgentCredential(context.Context, theauth.AgentCredential) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) AgentCredentialsByAgentID(context.Context, theauth.ULID) ([]theauth.AgentCredential, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) RevokeAgentCredential(context.Context, theauth.ULID, time.Time) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) UpdateAgentCredentialLastUsed(context.Context, theauth.ULID, time.Time) error {
	return errNotInCoreSuite
}

func (coreOnlyOAuth) InsertDelegationGrant(context.Context, theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	return theauth.DelegationGrant{}, errNotInCoreSuite
}

func (coreOnlyOAuth) DelegationGrantByID(context.Context, theauth.ULID) (*theauth.DelegationGrant, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) DelegationGrantByUserAgentResource(context.Context, theauth.ULID, theauth.ULID, string) (*theauth.DelegationGrant, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) DelegationGrantsByUserID(context.Context, theauth.ULID) ([]theauth.DelegationGrant, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) DelegationGrantsByAgentID(context.Context, theauth.ULID) ([]theauth.DelegationGrant, error) {
	return nil, errNotInCoreSuite
}

func (coreOnlyOAuth) RevokeDelegationGrant(context.Context, theauth.ULID, time.Time, string) error {
	return errNotInCoreSuite
}

var _ theauth.OAuthServerStorage = coreOnlyOAuth{}

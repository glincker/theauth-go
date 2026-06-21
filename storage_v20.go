package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// v2.0 (phase 1 + 2) storage extension interface.
//
// Backward compatibility: the root Storage interface is unchanged. The
// authorization server (Config.AuthorizationServer != nil) requires the
// configured storage to also satisfy OAuthServerStorage. New() type-asserts
// and returns ErrStorageMissingOAuthMethods when the assertion fails, so
// pre-v2.0 storage adapters keep compiling for non-AS deployments.
//
// The in-tree memory and postgres adapters satisfy OAuthServerStorage out of
// the box; consumers running custom adapters need to add the methods below
// before they can enable Config.AuthorizationServer.

// OAuthServerStorage is the subset of persistence required by the OAuth 2.1
// authorization server, the JWKS rotation goroutine, and dynamic client
// registration. Phase 1 + 2 only. Agent and delegation methods land in
// phase 3 + 4 alongside the corresponding service code.
type OAuthServerStorage interface {
	// OAuth clients (RFC 7591).
	InsertOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	// Authorization codes (single-use, 60-second TTL).
	InsertAuthorizationCode(ctx context.Context, c AuthorizationCode) error
	// ConsumeAuthorizationCode atomically loads-and-deletes a code row,
	// returning it. ErrStorageNotFound when absent or already consumed.
	ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// Refresh tokens (rotated on every use per RFC 9700 BCP).
	InsertRefreshToken(ctx context.Context, t RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID ULID, reason string) error

	// JWKS keys. Private bytes arrive encrypted; storage layer is unaware of
	// the encryption envelope.
	InsertJWKSKey(ctx context.Context, k JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error

	// Agents (v2.0 phase 3). Status transitions are recorded via
	// UpdateAgentStatus; last_active_at is updated by the introspection +
	// token paths so operators can see which agents are warm.
	InsertAgent(ctx context.Context, a Agent) (Agent, error)
	AgentByID(ctx context.Context, id ULID) (*Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*Agent, error)
	AgentsByOwner(ctx context.Context, owner AgentOwner) ([]Agent, error)
	UpdateAgentStatus(ctx context.Context, id ULID, status string, at time.Time) error
	UpdateAgentLastActive(ctx context.Context, id ULID, at time.Time) error

	// Agent credentials. Multiple rows per agent so a rotation can issue a
	// fresh credential before revoking the previous one. RevokeAgentCredential
	// sets revoked_at; AgentCredentialsByAgentID returns every row (callers
	// filter on RevokedAt themselves so audit views can list history).
	InsertAgentCredential(ctx context.Context, c AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID ULID) ([]AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id ULID, at time.Time) error
	UpdateAgentCredentialLastUsed(ctx context.Context, id ULID, at time.Time) error

	// Delegations (v2.0 phase 4). Uniqueness on (user_id, agent_id, resource)
	// is enforced at the database layer; InsertDelegationGrant returns a
	// wrapped error when violated. RevokeDelegationGrant sets revoked_at;
	// introspection on every resource server call honors the change inside
	// AuthorizationServerConfig.IntrospectionCacheTTL.
	InsertDelegationGrant(ctx context.Context, g DelegationGrant) (DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id ULID) (*DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID ULID, resource string) (*DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID ULID) ([]DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID ULID) ([]DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id ULID, at time.Time, reason string) error
}

// ErrStorageMissingOAuthMethods is returned by New when
// Config.AuthorizationServer is non-nil but Config.Storage does not satisfy
// OAuthServerStorage. The actual error value lives in internal/models (PR B
// architecture reorg, 2026-06-20) so subpackages can compare against it
// without importing root.
var ErrStorageMissingOAuthMethods = models.ErrStorageMissingOAuthMethods

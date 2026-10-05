package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// Storage is the full persistence contract: the embedding of every capability
// interface in storage_caps.go. Adapters live in sub-packages (storage/memory,
// storage/postgres) and the storage package re-exports it as storage.Storage.
// It is defined here so service code can reference it without an import cycle.
type Storage interface {
	UserStorage
	SessionStorage
	MagicLinkStorage
	PasswordStorage
	OAuthAccountStorage
	WebAuthnStorage
	TOTPStorage
	OrganizationStorage
	SAMLStorage
	SCIMStorage
	RBACStorage
	AuditStorage
}

// JWTBearerStorage is an optional extension that backends may implement to
// provide durable JTI replay prevention for RFC 7523 client assertions and
// bearer grant assertions. When the Storage passed to New also satisfies
// JWTBearerStorage, the AS uses it for all JTI checks; otherwise an
// in-process sync.Map is used (replay protection is lost on restart).
//
// Replay protection requires only two methods; SweepExpiredJTIs is a
// maintenance helper that operators call on a schedule (or via a
// background goroutine).
type JWTBearerStorage interface {
	// InsertJTI records a new jti. Returns ErrStorageNotFound when the jti
	// already exists within the replay window (the name is intentional: the
	// replay cache shares the same sentinel as other "not found" checks;
	// callers detect duplicates by inspecting whether the returned error is
	// ErrStorageNotFound). expiresAt is when the jti may be pruned.
	//
	// Implementation note: use a unique constraint on (jti) and return
	// ErrStorageNotFound on conflict (the generic "duplicate" signal).
	InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error
	// SweepExpiredJTIs removes all jti rows whose expiresAt is before the
	// supplied time. A no-op on an empty table.
	SweepExpiredJTIs(ctx context.Context, before time.Time) error
}

// ---------- v2.0 OAuth Server storage extension ----------

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

// ---------- CIBA (RFC 9509) storage extension ----------

// CIBAStorage is the optional persistence extension that storage backends must
// implement for CIBA to be active. When the storage passed to New does not
// also satisfy CIBAStorage, the /oauth/bc-authorize endpoint is not mounted
// and the AS metadata does not advertise CIBA fields.
//
// Memory and Postgres adapters in storage/memory and storage/postgres both
// implement CIBAStorage. Custom adapters only need to add these five methods
// before enabling Config.AuthorizationServer.CIBA.
type CIBAStorage interface {
	// InsertBackchannelRequest persists a new backchannel auth request.
	InsertBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	// BackchannelRequestByID returns the request keyed by auth_req_id.
	// Returns ErrStorageNotFound when absent.
	BackchannelRequestByID(ctx context.Context, authReqID string) (BackchannelRequest, error)

	// UpdateBackchannelRequest writes status changes and the approved token
	// strings atomically.
	UpdateBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	// DeleteBackchannelRequest removes the row. The library never calls this
	// automatically; operators call it for housekeeping.
	DeleteBackchannelRequest(ctx context.Context, authReqID string) error

	// TouchBackchannelPoll records the current time as the last poll instant
	// and stores a new poll interval, then returns the updated row.
	TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (BackchannelRequest, error)
}

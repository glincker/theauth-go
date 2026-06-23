package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// Storage is the persistence contract TheAuth depends on. Adapters live in
// sub-packages (storage/memory, storage/postgres). Defined here so that
// service code in this package can reference it without importing the
// storage sub-package (which would create an import cycle, because storage
// imports this package for the model types).
//
// The storage package re-exports this as storage.Storage so consumers can
// keep importing it from the conventional location.
//
// Moved from theauth.go into storage.go in PR H (2026-06-22) to bring
// theauth.go below the 500 LOC ceiling.
type Storage interface {
	// Users
	CreateUser(ctx context.Context, u User) (User, error)
	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByID(ctx context.Context, id ULID) (*User, error)
	MarkEmailVerified(ctx context.Context, userID ULID) error

	// Sessions
	CreateSession(ctx context.Context, s Session) (Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*Session, error)
	RevokeSession(ctx context.Context, id ULID) error
	RevokeUserSessions(ctx context.Context, userID ULID) error

	// Magic links
	CreateMagicLink(ctx context.Context, ml MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*MagicLink, error)

	// Email + password (v0.2)
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
	// UserByEmailWithPassword fetches a user along with their stored PHC hash.
	// passwordHash is "" if the account exists but has never set a password
	// (e.g. magic-link-only signup). Callers should treat empty hash as
	// "no password credential available" and surface invalid_credentials.
	UserByEmailWithPassword(ctx context.Context, email string) (user *User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)

	// OAuth accounts (v0.3)
	// UpsertOAuthAccount inserts or updates the row keyed by
	// (provider, provider_user_id). Returns the resulting row so callers
	// can use the assigned ID and timestamps. Implementations must encrypt
	// any token bytes before they reach storage; this layer only persists
	// what it is given.
	UpsertOAuthAccount(ctx context.Context, a OAuthAccount) (OAuthAccount, error)
	// OAuthAccountByProviderUserID looks up the row for a provider/user
	// pair. Returns ErrStorageNotFound when no row exists.
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)

	// OAuthAccountsByUserID returns all OAuth accounts linked to userID.
	// Returns an empty slice (not an error) when none exist.
	OAuthAccountsByUserID(ctx context.Context, userID ULID) ([]OAuthAccount, error)

	// MoveOAuthAccount reassigns the OAuth account row identified by
	// (provider, providerUserID) to newUserID. Returns ErrStorageNotFound
	// when no matching row exists.
	MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID ULID) error

	// DeleteOAuthAccountByProvider removes a single oauth_accounts row for
	// (userID, provider). Returns ErrStorageNotFound when no row exists.
	DeleteOAuthAccountByProvider(ctx context.Context, userID ULID, provider string) error

	// UserPasswordHashByID returns the stored Argon2id PHC string for the
	// user, or "" when the user has no password set.
	UserPasswordHashByID(ctx context.Context, userID ULID) (string, error)

	// MovePasswordHash copies the Argon2id hash from secondaryID to
	// primaryID (overwriting any hash primaryID already has) and then
	// clears secondaryID's hash. A no-op if secondaryID has no hash.
	MovePasswordHash(ctx context.Context, primaryID, secondaryID ULID) error

	// MoveWebAuthnCredentials reassigns every WebAuthn credential row owned
	// by secondaryID to primaryID.
	MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID ULID) error

	// MoveTOTPSecret reassigns the TOTP secret row of secondaryID to
	// primaryID. If primaryID already has a confirmed secret the secondary
	// secret is dropped (not overwritten) to preserve the active primary
	// factor. A no-op if secondaryID has no TOTP secret.
	MoveTOTPSecret(ctx context.Context, primaryID, secondaryID ULID) error

	// Sessions: v0.5 step-up additions
	// CreateSessionWithAuthLevel mints a session whose AuthLevel column is
	// set to the supplied value (typically AuthLevelPending2FA). Mirrors
	// CreateSession otherwise. CreateSession itself continues to default
	// to AuthLevelFull at the DDL layer so older callers see no change.
	CreateSessionWithAuthLevel(ctx context.Context, s Session) (Session, error)
	// UpdateSessionAuthLevel rewrites a single session's AuthLevel column.
	// Used by /auth/totp/verify to promote a pending session to full.
	UpdateSessionAuthLevel(ctx context.Context, id ULID, level string) error

	// WebAuthn (v0.5)
	InsertWebAuthnCredential(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error)
	WebAuthnCredentialsByUserID(ctx context.Context, userID ULID) ([]WebAuthnCredential, error)
	// WebAuthnCredentialByCredentialID returns the row keyed by the raw
	// authenticator credential ID, or ErrStorageNotFound when missing.
	WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	// UpdateWebAuthnSignCount atomically writes a strictly greater sign
	// count and bumps last_used_at. Returns ErrReplayDetected when the
	// new count is not strictly greater than the stored value (the
	// canonical replay signal per WebAuthn L2 / L3). Returns
	// ErrStorageNotFound when the credential does not exist.
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error
	// DeleteWebAuthnCredential removes a credential by ID, scoped to the
	// owning user. Returns ErrStorageNotFound when the row does not exist
	// or does not belong to the caller (no leak on cross-user lookup).
	DeleteWebAuthnCredential(ctx context.Context, id ULID, userID ULID) error

	// TOTP (v0.5)
	// UpsertPendingTOTPSecret writes an encrypted secret with
	// confirmed_at = NULL. Replaces any prior unconfirmed secret for the
	// same user; preserves a confirmed one untouched (re-enrollment
	// requires DeleteTOTPSecret first).
	UpsertPendingTOTPSecret(ctx context.Context, s TOTPSecret) error
	// ConfirmTOTPSecret sets confirmed_at on the user's pending secret.
	// Returns ErrStorageNotFound when no pending row exists.
	ConfirmTOTPSecret(ctx context.Context, userID ULID, at time.Time) error
	TOTPSecretByUserID(ctx context.Context, userID ULID) (*TOTPSecret, error)
	DeleteTOTPSecret(ctx context.Context, userID ULID) error

	InsertRecoveryCodes(ctx context.Context, codes []RecoveryCode) error
	// ConsumeRecoveryCode walks the user's unused codes, locates the one
	// whose hash matches via crypto.VerifyRecoveryCode, and marks it used
	// atomically. Returns ErrStorageNotFound when no matching unused code
	// exists (covers wrong code, reused code, and cross-user mismatch).
	ConsumeRecoveryCode(ctx context.Context, userID ULID, code string, at time.Time) error

	// ---------- v0.7 multi-tenancy + SAML + SCIM ----------
	// All methods below are additive; existing single-tenant deployments
	// never invoke them because the corresponding handlers are mounted
	// only when Config.Organizations / SAML / SCIM are non-nil.

	// Organizations + membership
	InsertOrganization(ctx context.Context, o Organization) (Organization, error)
	OrganizationByID(ctx context.Context, id ULID) (*Organization, error)
	OrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, o Organization) error
	DeleteOrganization(ctx context.Context, id ULID) error

	UpsertOrganizationMember(ctx context.Context, m OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID ULID) error
	OrganizationMembersByOrg(ctx context.Context, orgID ULID) ([]OrganizationMember, error)
	OrganizationsByUser(ctx context.Context, userID ULID) ([]Organization, error)
	OrganizationMemberRole(ctx context.Context, orgID, userID ULID) (string, error)

	SetSessionActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error

	// SAML connections and identities
	InsertSAMLConnection(ctx context.Context, c SAMLConnection) (SAMLConnection, error)
	UpdateSAMLConnectionRow(ctx context.Context, c SAMLConnection) error
	DeleteSAMLConnection(ctx context.Context, id ULID) error
	SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error)
	SAMLConnectionsByOrg(ctx context.Context, orgID ULID) ([]SAMLConnection, error)

	UpsertSAMLIdentity(ctx context.Context, i SAMLIdentity) (SAMLIdentity, error)
	SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID ULID, nameID string) (*SAMLIdentity, error)
	TouchSAMLIdentityLastLogin(ctx context.Context, id ULID, at time.Time) error

	// SCIM tokens
	InsertSCIMToken(ctx context.Context, t SCIMToken) (SCIMToken, error)
	SCIMTokenByHash(ctx context.Context, hash []byte) (*SCIMToken, error)
	SCIMTokensByOrg(ctx context.Context, orgID ULID) ([]SCIMToken, error)
	RevokeSCIMTokenByID(ctx context.Context, id ULID, at time.Time) error
	TouchSCIMTokenLastUsed(ctx context.Context, id ULID, at time.Time) error

	// SCIM user + group lookups scoped to a single organization
	ListUsersByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMUserFilter) (users []User, total int, err error)
	ListGroupsByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMGroupFilter) (groups []Group, total int, err error)
	UserByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*User, error)
	UpdateUserSCIM(ctx context.Context, u User) error

	// Groups (SCIM)
	InsertGroup(ctx context.Context, g Group) (Group, error)
	GroupByID(ctx context.Context, id ULID) (*Group, error)
	GroupByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*Group, error)
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, id ULID) error
	SetGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	AddGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	RemoveGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	GroupMembers(ctx context.Context, groupID ULID) ([]ULID, error)

	// ---------- v1.0 RBAC ----------
	// Permissions form a global catalog (no org scope). Insert is idempotent
	// on the name unique index; duplicate names return the existing row
	// rather than an error so seed runs at app start are safe.
	InsertPermission(ctx context.Context, p Permission) (Permission, error)
	PermissionByName(ctx context.Context, name string) (*Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)

	InsertRole(ctx context.Context, r Role) (Role, error)
	UpdateRoleRow(ctx context.Context, r Role) (Role, error)
	DeleteRole(ctx context.Context, id ULID) error
	RoleByID(ctx context.Context, id ULID) (*Role, error)
	RoleByOrgAndName(ctx context.Context, orgID *ULID, name string) (*Role, error)
	RolesByOrganization(ctx context.Context, orgID *ULID) ([]Role, error)

	SetRolePermissions(ctx context.Context, roleID ULID, permissionIDs []ULID) error
	// PermissionsByRole returns the permission-name slice for one role.
	// The names are looked up by joining role_permissions to permissions.
	PermissionsByRole(ctx context.Context, roleID ULID) ([]string, error)

	GrantUserRole(ctx context.Context, ur UserRole) error
	RevokeUserRole(ctx context.Context, userID, roleID ULID) error
	RolesForUser(ctx context.Context, userID ULID, orgID *ULID) ([]Role, error)
	PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error)
	CountUsersWithPermissionInOrg(ctx context.Context, orgID ULID, perm string) (int, error)

	// ---------- v1.0 audit log ----------
	// InsertAuditEvents writes a batch in one round trip. Append-only;
	// adapters MUST NOT expose UPDATE or DELETE for audit rows. Failure
	// returns an error; the writer goroutine logs it and increments
	// Stats.AuditFailed without retrying (documented tradeoff).
	InsertAuditEvents(ctx context.Context, events []AuditEvent) error
	QueryAuditEvents(ctx context.Context, q AuditQuery) (events []AuditEvent, nextCursor string, err error)
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

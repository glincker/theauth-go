package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/importer"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/storagestub"
	"github.com/glincker/theauth-go/v2/internal/totp"
)

// Storage is the full persistence contract: the embedding of every capability
// interface in this file. Adapters live in sub-packages (storage/memory,
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

// ---------- RFC 8628 device grant and registration tokens ----------

// DeviceAuthorizationStorage is the optional persistence extension for the
// OAuth device grant (Config.AuthorizationServer.DeviceAuthorization). Lookups
// return ErrStorageNotFound on a miss. Decide and Consume are conditional
// updates that report whether they applied. Memory, Postgres and MySQL
// implement it; run storagetest.RunDeviceAuthorizations against a custom one.
type DeviceAuthorizationStorage interface {
	InsertDeviceAuthorization(ctx context.Context, d DeviceAuthorization) error
	DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*DeviceAuthorization, error)
	DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*DeviceAuthorization, error)
	DecideDeviceAuthorization(ctx context.Context, id ULID, status string, userID ULID, now time.Time) (bool, error)
	RecordDeviceAuthorizationPoll(ctx context.Context, id ULID, polledAt time.Time, intervalSeconds int) error
	ConsumeDeviceAuthorization(ctx context.Context, id ULID, now time.Time) (bool, error)
	DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error)
}

// OpaqueTokenStorage is the optional persistence extension behind opaque
// (reference) access tokens, enabled per client through
// AuthorizationServerConfig.TokenPolicy. Only token hashes are stored.
// Lookups return ErrStorageNotFound on a miss. Revoking an unknown token is
// not an error. Run storagetest.RunOpaqueTokens against a custom
// implementation.
type OpaqueTokenStorage interface {
	InsertOpaqueAccessToken(ctx context.Context, t OpaqueAccessToken) error
	OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*OpaqueAccessToken, error)
	RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error
}

// RegistrationTokenStorage is the optional persistence extension for initial
// access tokens (admin API plus POST /oauth/register). Run
// storagetest.RunRegistrationTokens against a custom implementation.
type RegistrationTokenStorage interface {
	InsertRegistrationToken(ctx context.Context, t RegistrationToken) error
	RegistrationTokenByHash(ctx context.Context, hash []byte) (*RegistrationToken, error)
	RegistrationTokenByID(ctx context.Context, id ULID) (*RegistrationToken, error)
	ListRegistrationTokens(ctx context.Context, orgID *ULID) ([]RegistrationToken, error)
	RevokeRegistrationToken(ctx context.Context, id ULID, at time.Time) (bool, error)
	RedeemRegistrationToken(ctx context.Context, id ULID, now time.Time) (bool, error)
	RefundRegistrationToken(ctx context.Context, id ULID) error
}

// UserStorage covers user records and email verification.
type UserStorage interface {
	CreateUser(ctx context.Context, u User) (User, error)
	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByID(ctx context.Context, id ULID) (*User, error)
	MarkEmailVerified(ctx context.Context, userID ULID) error
}

// SessionStorage covers session issuance, lookup, revocation and auth-level step-up.
type SessionStorage interface {
	CreateSession(ctx context.Context, s Session) (Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*Session, error)
	SessionByID(ctx context.Context, id ULID) (*Session, error)
	RevokeSession(ctx context.Context, id ULID) error
	RevokeUserSessions(ctx context.Context, userID ULID) error
	// CreateSessionWithAuthLevel mints a session whose AuthLevel column is
	// set to the supplied value (typically AuthLevelPending2FA). Mirrors
	// CreateSession otherwise. CreateSession itself continues to default
	// to AuthLevelFull at the DDL layer so older callers see no change.
	CreateSessionWithAuthLevel(ctx context.Context, s Session) (Session, error)
	// UpdateSessionAuthLevel rewrites a single session's AuthLevel column.
	// Used by /auth/totp/verify to promote a pending session to full.
	UpdateSessionAuthLevel(ctx context.Context, id ULID, level string) error
}

// MagicLinkStorage covers single-use magic-link tokens.
type MagicLinkStorage interface {
	CreateMagicLink(ctx context.Context, ml MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*MagicLink, error)
}

// PasswordStorage covers password hashes and reset tokens.
type PasswordStorage interface {
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
	// UserByEmailWithPassword fetches a user along with their stored PHC hash.
	// passwordHash is "" if the account exists but has never set a password
	// (e.g. magic-link-only signup). Callers should treat empty hash as
	// "no password credential available" and surface invalid_credentials.
	UserByEmailWithPassword(ctx context.Context, email string) (user *User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
	// UserPasswordHashByID returns the stored Argon2id PHC string for the
	// user, or "" when the user has no password set.
	UserPasswordHashByID(ctx context.Context, userID ULID) (string, error)

	// MovePasswordHash copies the Argon2id hash from secondaryID to
	// primaryID (overwriting any hash primaryID already has) and then
	// clears secondaryID's hash. A no-op if secondaryID has no hash.
	MovePasswordHash(ctx context.Context, primaryID, secondaryID ULID) error
}

// OAuthAccountStorage covers linked third-party OAuth accounts.
type OAuthAccountStorage interface {
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
}

// WebAuthnStorage covers WebAuthn passkey credentials.
type WebAuthnStorage interface {
	// MoveWebAuthnCredentials reassigns every WebAuthn credential row owned
	// by secondaryID to primaryID.
	MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID ULID) error
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
	// UpdateWebAuthnBackupFlags records the WebAuthn backup-eligible / backup
	// -state flags for a credential that had none stored (a row written before
	// the backup_eligible / backup_state columns existed). It is the
	// trust-on-first-use reconciliation write for legacy synced passkeys and
	// is idempotent. Implementations should return nil when the credential is
	// missing rather than error; the caller treats any failure as non-fatal
	// (a failed reconciliation must never fail an already-verified login).
	UpdateWebAuthnBackupFlags(ctx context.Context, credentialID []byte, backupEligible, backupState bool) error
	// DeleteWebAuthnCredential removes a credential by ID, scoped to the
	// owning user. Returns ErrStorageNotFound when the row does not exist
	// or does not belong to the caller (no leak on cross-user lookup).
	DeleteWebAuthnCredential(ctx context.Context, id ULID, userID ULID) error
}

// TOTPStorage covers TOTP secrets and recovery codes.
type TOTPStorage interface {
	// MoveTOTPSecret reassigns the TOTP secret row of secondaryID to
	// primaryID. If primaryID already has a confirmed secret the secondary
	// secret is dropped (not overwritten) to preserve the active primary
	// factor. A no-op if secondaryID has no TOTP secret.
	MoveTOTPSecret(ctx context.Context, primaryID, secondaryID ULID) error
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
}

// OrganizationStorage covers organizations, membership and the session active-organization pointer.
type OrganizationStorage interface {
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
}

// SAMLStorage covers SAML connections and identities.
type SAMLStorage interface {
	InsertSAMLConnection(ctx context.Context, c SAMLConnection) (SAMLConnection, error)
	UpdateSAMLConnectionRow(ctx context.Context, c SAMLConnection) error
	DeleteSAMLConnection(ctx context.Context, id ULID) error
	SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error)
	SAMLConnectionsByOrg(ctx context.Context, orgID ULID) ([]SAMLConnection, error)

	UpsertSAMLIdentity(ctx context.Context, i SAMLIdentity) (SAMLIdentity, error)
	SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID ULID, nameID string) (*SAMLIdentity, error)
	TouchSAMLIdentityLastLogin(ctx context.Context, id ULID, at time.Time) error
}

// SCIMStorage covers SCIM tokens, organization-scoped user lookups and groups.
type SCIMStorage interface {
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
}

// RBACStorage covers permissions, roles and user-role grants.
type RBACStorage interface {
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
}

// AuditStorage covers the append-only audit log.
type AuditStorage interface {
	// InsertAuditEvents writes a batch in one round trip. Append-only;
	// adapters MUST NOT expose UPDATE or DELETE for audit rows. Failure
	// returns an error; the writer goroutine logs it and increments
	// Stats.AuditFailed without retrying (documented tradeoff).
	InsertAuditEvents(ctx context.Context, events []AuditEvent) error
	QueryAuditEvents(ctx context.Context, q AuditQuery) (events []AuditEvent, nextCursor string, err error)
}

// CoreStorage is the minimal capability set for email and password sign-in,
// sessions and magic links. Set it as Config.CoreStorage to skip the
// organization, SAML, SCIM, WebAuthn, TOTP and RBAC methods.
type CoreStorage interface {
	UserStorage
	SessionStorage
	MagicLinkStorage
	PasswordStorage
}

// ErrStorageMissingCapability is returned by New when an enabled feature needs
// a capability interface the configured storage lacks, and by the stub methods
// of a storage assembled from Config.CoreStorage.
var ErrStorageMissingCapability = models.ErrStorageMissingCapability

func missingCapability(name string) error {
	return fmt.Errorf("%w: %s", ErrStorageMissingCapability, name)
}

// assembledStorage lets services typed against the full Storage run on a
// CoreStorage: capabilities the adapter lacks are filled with stubs that
// return ErrStorageMissingCapability. New has already rejected configs that
// enable a feature needing a stubbed capability.
type assembledStorage struct {
	CoreStorage
	OAuthAccountStorage
	WebAuthnStorage
	TOTPStorage
	OrganizationStorage
	SAMLStorage
	SCIMStorage
	RBACStorage
	AuditStorage
}

func assembleStorage(raw CoreStorage) Storage {
	if full, ok := raw.(Storage); ok {
		return full
	}
	s := assembledStorage{
		CoreStorage:         raw,
		OAuthAccountStorage: storagestub.OAuthAccount{},
		WebAuthnStorage:     storagestub.WebAuthn{},
		TOTPStorage:         storagestub.TOTP{},
		OrganizationStorage: storagestub.Organization{},
		SAMLStorage:         storagestub.SAML{},
		SCIMStorage:         storagestub.SCIM{},
		RBACStorage:         storagestub.RBAC{},
		AuditStorage:        storagestub.Audit{},
	}
	if v, ok := raw.(OAuthAccountStorage); ok {
		s.OAuthAccountStorage = v
	}
	if v, ok := raw.(WebAuthnStorage); ok {
		s.WebAuthnStorage = v
	}
	if v, ok := raw.(TOTPStorage); ok {
		s.TOTPStorage = v
	}
	if v, ok := raw.(OrganizationStorage); ok {
		s.OrganizationStorage = v
	}
	if v, ok := raw.(SAMLStorage); ok {
		s.SAMLStorage = v
	}
	if v, ok := raw.(SCIMStorage); ok {
		s.SCIMStorage = v
	}
	if v, ok := raw.(RBACStorage); ok {
		s.RBACStorage = v
	}
	if v, ok := raw.(AuditStorage); ok {
		s.AuditStorage = v
	}
	return s
}

// selectStorage enforces that exactly one of Config.Storage and
// Config.CoreStorage is set and records it as the raw storage that optional
// extension interfaces are asserted against.
func selectStorage(cfg *Config) error {
	switch {
	case cfg.Storage == nil && cfg.CoreStorage == nil:
		return errors.New("theauth: Config.Storage or Config.CoreStorage is required")
	case cfg.Storage != nil && cfg.CoreStorage != nil:
		return errors.New("theauth: Config.Storage and Config.CoreStorage are mutually exclusive")
	case cfg.Storage != nil:
		cfg.storageRaw = cfg.Storage
	default:
		cfg.storageRaw = cfg.CoreStorage
	}
	return nil
}

// checkStorageCapabilities returns ErrStorageMissingCapability, naming the
// feature and the capability, when an enabled feature needs a capability the
// raw storage does not implement.
func checkStorageCapabilities(cfg *Config) error {
	raw := cfg.storageRaw
	_, oauthAcct := raw.(OAuthAccountStorage)
	_, webauthn := raw.(WebAuthnStorage)
	_, totp := raw.(TOTPStorage)
	_, orgs := raw.(OrganizationStorage)
	_, saml := raw.(SAMLStorage)
	_, scim := raw.(SCIMStorage)
	_, rbac := raw.(RBACStorage)
	_, audit := raw.(AuditStorage)
	_, apiTokens := raw.(APITokenStorage)
	_, deviceCodes := raw.(DeviceCodeStorage)
	reqs := []struct {
		enabled   bool
		feature   string
		capName   string
		satisfied bool
	}{
		{len(cfg.Providers) > 0, "Providers", "OAuthAccountStorage", oauthAcct},
		{cfg.WebAuthn != nil, "WebAuthn", "WebAuthnStorage", webauthn},
		{cfg.TOTP != nil, "TOTP", "TOTPStorage", totp},
		{cfg.Organizations != nil, "Organizations", "OrganizationStorage", orgs},
		{cfg.SAML != nil, "SAML", "SAMLStorage", saml},
		{cfg.SCIM != nil, "SCIM", "SCIMStorage", scim},
		{cfg.RBAC != nil, "RBAC", "RBACStorage", rbac},
		{cfg.Audit != nil, "Audit", "AuditStorage", audit},
		{cfg.APITokens != nil, "APITokens", "APITokenStorage", apiTokens},
		{cfg.APITokens != nil && cfg.APITokens.Device != nil, "APITokens.Device", "DeviceCodeStorage", deviceCodes},
		{cfg.AccountUX, "AccountUX", "OAuthAccountStorage", oauthAcct},
		{cfg.AccountUX, "AccountUX", "WebAuthnStorage", webauthn},
		{cfg.AccountUX, "AccountUX", "TOTPStorage", totp},
	}
	for _, r := range reqs {
		if r.enabled && !r.satisfied {
			return fmt.Errorf("%w: Config.%s requires %s", ErrStorageMissingCapability, r.feature, r.capName)
		}
	}
	return nil
}

// TOTPReplayStorage is an optional capability that makes TOTP replay
// protection durable and shared across processes. Without it the library
// tracks the last used step in process memory only.
type TOTPReplayStorage interface {
	// AdvanceTOTPStep atomically records step as the user's last used TOTP
	// time-step. It returns false, and changes nothing, when step is not
	// strictly greater than the stored value (a replayed or older code).
	AdvanceTOTPStep(ctx context.Context, userID ULID, step int64) (advanced bool, err error)
}

// UserCountStorage is an optional capability required by Config.Bootstrap
// to detect whether the first administrator has been created yet.
type UserCountStorage interface {
	// CountUsers returns the total number of user records.
	CountUsers(ctx context.Context) (int, error)
}

// WebAuthnRenameStorage is the optional capability behind passkey rename
// (PATCH /auth/webauthn/credentials/{id}). Adapters that do not implement it
// answer 501 on that route; everything else keeps working.
type WebAuthnRenameStorage interface {
	// RenameWebAuthnCredential sets the display name of the credential
	// identified by id when it belongs to userID. Returns ErrStorageNotFound
	// when no such row exists.
	RenameWebAuthnCredential(ctx context.Context, id, userID ULID, name string) error
}

// RecoveryCodeStorage is the optional capability behind GET /auth/totp
// (remaining recovery codes) and POST /auth/totp/recovery-codes. Without it
// the status route reports -1 remaining and regeneration answers 501.
type RecoveryCodeStorage interface {
	// CountUnusedRecoveryCodes returns how many unused codes userID holds.
	CountUnusedRecoveryCodes(ctx context.Context, userID ULID) (int, error)
	// ReplaceRecoveryCodes atomically deletes every code of userID and
	// inserts codes.
	ReplaceRecoveryCodes(ctx context.Context, userID ULID, codes []RecoveryCode) error
}

// TOTPStatus reports whether TOTP is enrolled and how many recovery codes
// remain (-1 when the storage cannot count them).
type TOTPStatus = totp.Status

// TOTPStatus returns the user's TOTP enrollment state.
func (a *TheAuth) TOTPStatus(ctx context.Context, userID ULID) (TOTPStatus, error) {
	return a.totpSvc.Status(ctx, userID)
}

// RegenerateRecoveryCodes replaces the user's recovery codes and returns the
// new plaintext codes once. The user must have TOTP enrolled.
func (a *TheAuth) RegenerateRecoveryCodes(ctx context.Context, userID ULID) ([]string, error) {
	return a.totpSvc.RegenerateRecoveryCodes(ctx, userID)
}

// RenamePasskey changes the display name of one of the user's passkeys.
func (a *TheAuth) RenamePasskey(ctx context.Context, id, userID ULID, name string) error {
	return a.webauthnSvc.RenameCredential(ctx, id, userID, name)
}

// SessionLink is a short-lived, single-use grant that exchanges for a session.
type SessionLink = models.SessionLink

// SessionManagementStorage is the optional capability behind end-user session
// lists, idle timeout, last-seen tracking and step-up. It is detected by type
// assertion and is not part of Storage.
type SessionManagementStorage interface {
	// ListUserSessions returns the user's sessions that are neither revoked
	// nor past ExpiresAt, newest first.
	ListUserSessions(ctx context.Context, userID ULID) ([]Session, error)
	// TouchSession advances LastSeenAt to at. It never moves it backwards
	// and returns ErrStorageNotFound for an unknown id.
	TouchSession(ctx context.Context, id ULID, at time.Time) error
	// RevokeOtherUserSessions revokes every live session of userID except
	// keep and returns how many it revoked.
	RevokeOtherUserSessions(ctx context.Context, userID, keep ULID) (int, error)
	// RevokeSessionsByCredential revokes every live session tied to
	// credentialID and returns how many it revoked.
	RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error)
	// SetSessionElevatedUntil sets or clears ElevatedUntil on one session.
	SetSessionElevatedUntil(ctx context.Context, id ULID, until *time.Time) error
}

// SessionLinkStorage is the optional capability behind programmatic session
// links.
type SessionLinkStorage interface {
	CreateSessionLink(ctx context.Context, l SessionLink) error
	// ConsumeSessionLink atomically marks the link used and returns it. It
	// returns ErrStorageNotFound when the hash is unknown, already used, or
	// expired at now.
	ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*SessionLink, error)
}

// ErrImportDuplicate is returned by the Import helpers when the record already exists; callers may treat it as already imported.
var ErrImportDuplicate = models.ErrImportDuplicate

// ErrImportInvalid wraps every Import helper validation failure.
var ErrImportInvalid = importer.ErrImportInvalid

// ImportUserStorage is the storage surface ImportUserTo needs.
type ImportUserStorage interface {
	UserStorage
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
}

// ImportedUser is an existing account to insert. PasswordHash is stored verbatim and may be empty.
type ImportedUser = importer.ImportedUser

// ImportedTOTP is an existing, already-enrolled TOTP secret.
type ImportedTOTP = importer.ImportedTOTP

// ImportedWebAuthnCredential is an existing passkey or security key.
type ImportedWebAuthnCredential = importer.ImportedWebAuthnCredential

// ImportUserTo inserts an existing user and its password hash into store, with no TheAuth instance.
func ImportUserTo(ctx context.Context, store ImportUserStorage, in ImportedUser) (User, error) {
	if store == nil {
		return User{}, importer.ErrNilStorage
	}
	return importer.ImportUserTo(ctx, store, in)
}

// ImportTOTPSecretTo encrypts the plaintext secret with encryptionKey and stores it as confirmed, with no TheAuth instance.
func ImportTOTPSecretTo(ctx context.Context, store TOTPStorage, encryptionKey []byte, in ImportedTOTP) error {
	if store == nil {
		return importer.ErrNilStorage
	}
	return importer.ImportTOTPSecretTo(ctx, store, encryptionKey, in)
}

// ImportWebAuthnCredentialTo inserts an existing credential into store, with no TheAuth instance.
func ImportWebAuthnCredentialTo(ctx context.Context, store WebAuthnStorage, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	if store == nil {
		return WebAuthnCredential{}, importer.ErrNilStorage
	}
	return importer.ImportWebAuthnCredentialTo(ctx, store, in)
}

// ImportUser inserts an existing user through the configured storage; see ImportUserTo.
func (a *TheAuth) ImportUser(ctx context.Context, in ImportedUser) (User, error) {
	return ImportUserTo(ctx, a.storage, in)
}

// ImportTOTPSecret encrypts a plaintext secret with Config.EncryptionKey and stores it as confirmed; see ImportTOTPSecretTo.
func (a *TheAuth) ImportTOTPSecret(ctx context.Context, in ImportedTOTP) error {
	return ImportTOTPSecretTo(ctx, a.storage, a.encryptionKey, in)
}

// ImportWebAuthnCredential inserts an existing credential through the configured storage; see ImportWebAuthnCredentialTo.
func (a *TheAuth) ImportWebAuthnCredential(ctx context.Context, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	return ImportWebAuthnCredentialTo(ctx, a.storage, in)
}

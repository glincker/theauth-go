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

// Storage is the full persistence contract, embedding every capability interface in this file.
// Adapters live in sub-packages (storage/memory, storage/postgres); it is defined here to avoid an
// import cycle.
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

// JWTBearerStorage is an optional extension giving durable JTI replay prevention for RFC 7523
// assertions. Without it the AS falls back to an in-process map, which loses replay protection on
// restart.
type JWTBearerStorage interface {
	// InsertJTI records a new jti. It returns ErrStorageNotFound when the jti already exists in the
	// replay window (the generic duplicate signal, so implement it with a unique constraint on jti).
	// expiresAt is when the jti may be pruned.
	InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error
	// SweepExpiredJTIs removes jti rows expiring before the given time.
	SweepExpiredJTIs(ctx context.Context, before time.Time) error
}

// OAuthServerStorage is required when Config.AuthorizationServer is set; New returns
// ErrStorageMissingOAuthMethods otherwise. The in-tree memory and postgres adapters satisfy it.

// OAuthServerStorage is the persistence needed by the OAuth 2.1 authorization server, the JWKS
// rotation goroutine and dynamic client registration.
type OAuthServerStorage interface {
	InsertOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	InsertAuthorizationCode(ctx context.Context, c AuthorizationCode) error
	// ConsumeAuthorizationCode atomically loads and deletes a code row. It returns ErrStorageNotFound
	// when absent or already used.
	ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	InsertRefreshToken(ctx context.Context, t RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID ULID, reason string) error

	// InsertJWKSKey stores a key whose private bytes arrive already encrypted.
	InsertJWKSKey(ctx context.Context, k JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error

	// Agents. Status transitions go through UpdateAgentStatus; last_active_at is touched by
	// introspection and token paths.
	InsertAgent(ctx context.Context, a Agent) (Agent, error)
	AgentByID(ctx context.Context, id ULID) (*Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*Agent, error)
	AgentsByOwner(ctx context.Context, owner AgentOwner) ([]Agent, error)
	UpdateAgentStatus(ctx context.Context, id ULID, status string, at time.Time) error
	UpdateAgentLastActive(ctx context.Context, id ULID, at time.Time) error

	// Agent credentials. Rotation inserts a fresh row before revoking the old one; callers filter on
	// RevokedAt themselves.
	InsertAgentCredential(ctx context.Context, c AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID ULID) ([]AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id ULID, at time.Time) error
	UpdateAgentCredentialLastUsed(ctx context.Context, id ULID, at time.Time) error

	// Delegations. Uniqueness on (user_id, agent_id, resource) is enforced by the database.
	// Revocations reach resource servers within AuthorizationServerConfig.IntrospectionCacheTTL.
	InsertDelegationGrant(ctx context.Context, g DelegationGrant) (DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id ULID) (*DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID ULID, resource string) (*DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID ULID) ([]DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID ULID) ([]DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id ULID, at time.Time, reason string) error
}

// ErrStorageMissingOAuthMethods is returned by New when Config.AuthorizationServer is set but
// Config.Storage does not satisfy OAuthServerStorage.
var ErrStorageMissingOAuthMethods = models.ErrStorageMissingOAuthMethods

// CIBAStorage is the optional persistence for CIBA. Without it /oauth/bc-authorize is not mounted.
// Memory and Postgres implement it; custom adapters must add these methods before enabling
// Config.AuthorizationServer.CIBA.
type CIBAStorage interface {
	InsertBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	// BackchannelRequestByID returns the request keyed by auth_req_id, or ErrStorageNotFound.
	BackchannelRequestByID(ctx context.Context, authReqID string) (BackchannelRequest, error)

	// UpdateBackchannelRequest writes status changes and approved token strings atomically.
	UpdateBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	DeleteBackchannelRequest(ctx context.Context, authReqID string) error

	TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (BackchannelRequest, error)
}

// BackchannelStatusConsumed marks an approved CIBA request whose tokens were already delivered.
const BackchannelStatusConsumed = "consumed"

// BackchannelRedeemer is an optional CIBAStorage capability that makes token delivery single use.
// RedeemBackchannelRequest atomically moves an approved, unexpired request to consumed and returns
// its tokens. Exactly one concurrent caller gets ok == true. Without it the AS uses an in-process
// lock, correct only on one node; multi-node needs this capability.
type BackchannelRedeemer interface {
	RedeemBackchannelRequest(ctx context.Context, authReqID string, now time.Time) (BackchannelRequest, bool, error)
}

// DeviceAuthorizationStorage is the optional persistence for the RFC 8628 device grant. Decide and
// Consume are conditional updates that report whether they applied.
type DeviceAuthorizationStorage interface {
	InsertDeviceAuthorization(ctx context.Context, d DeviceAuthorization) error
	DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*DeviceAuthorization, error)
	DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*DeviceAuthorization, error)
	DecideDeviceAuthorization(ctx context.Context, id ULID, status string, userID ULID, now time.Time) (bool, error)
	RecordDeviceAuthorizationPoll(ctx context.Context, id ULID, polledAt time.Time, intervalSeconds int) error
	ConsumeDeviceAuthorization(ctx context.Context, id ULID, now time.Time) (bool, error)
	DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error)
}

// OpaqueTokenStorage is the optional persistence behind opaque (reference) access tokens, enabled
// per client through TokenPolicy. Only token hashes are stored.
type OpaqueTokenStorage interface {
	InsertOpaqueAccessToken(ctx context.Context, t OpaqueAccessToken) error
	OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*OpaqueAccessToken, error)
	RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error
}

// RegistrationTokenStorage is the optional persistence for initial access tokens.
type RegistrationTokenStorage interface {
	InsertRegistrationToken(ctx context.Context, t RegistrationToken) error
	RegistrationTokenByHash(ctx context.Context, hash []byte) (*RegistrationToken, error)
	RegistrationTokenByID(ctx context.Context, id ULID) (*RegistrationToken, error)
	ListRegistrationTokens(ctx context.Context, orgID *ULID) ([]RegistrationToken, error)
	RevokeRegistrationToken(ctx context.Context, id ULID, at time.Time) (bool, error)
	RedeemRegistrationToken(ctx context.Context, id ULID, now time.Time) (bool, error)
	RefundRegistrationToken(ctx context.Context, id ULID) error
}

// DeviceIdentityStorage is the optional persistence for constrained devices and their join tokens.
type DeviceIdentityStorage interface {
	InsertDevice(ctx context.Context, d Device) error
	DeviceByID(ctx context.Context, id ULID) (*Device, error)
	ListDevices(ctx context.Context, orgID *ULID) ([]Device, error)
	RevokeDevice(ctx context.Context, id ULID, at time.Time) (bool, error)
	TouchDevice(ctx context.Context, id ULID, at time.Time) error

	InsertDeviceJoinToken(ctx context.Context, t DeviceJoinToken) error
	DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*DeviceJoinToken, error)
	DeviceJoinTokenByID(ctx context.Context, id ULID) (*DeviceJoinToken, error)
	RevokeDeviceJoinToken(ctx context.Context, id ULID, at time.Time) (bool, error)
	RedeemDeviceJoinToken(ctx context.Context, id, deviceID ULID, now time.Time) (bool, error)
	RefundDeviceJoinToken(ctx context.Context, id ULID) error
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
	// CreateSessionWithAuthLevel mints a session at the supplied auth level (typically
	// AuthLevelPending2FA). CreateSession keeps defaulting to AuthLevelFull.
	CreateSessionWithAuthLevel(ctx context.Context, s Session) (Session, error)
	// UpdateSessionAuthLevel rewrites a session's auth level. TOTP verification uses it to promote a
	// pending session.
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
	// UserByEmailWithPassword fetches a user with their stored PHC hash. The hash is "" when the
	// account has no password (for example magic-link-only signup), which must surface as
	// invalid_credentials.
	UserByEmailWithPassword(ctx context.Context, email string) (user *User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
	UserPasswordHashByID(ctx context.Context, userID ULID) (string, error)

	// MovePasswordHash copies the Argon2id hash from secondaryID to primaryID (overwriting it) and
	// clears secondaryID's.
	MovePasswordHash(ctx context.Context, primaryID, secondaryID ULID) error
}

// OAuthAccountStorage covers linked third-party OAuth accounts.
type OAuthAccountStorage interface {
	// UpsertOAuthAccount inserts or updates the row keyed by (provider, provider_user_id).
	// Implementations must encrypt token bytes before they reach storage.
	UpsertOAuthAccount(ctx context.Context, a OAuthAccount) (OAuthAccount, error)
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)

	OAuthAccountsByUserID(ctx context.Context, userID ULID) ([]OAuthAccount, error)

	MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID ULID) error

	DeleteOAuthAccountByProvider(ctx context.Context, userID ULID, provider string) error
}

// WebAuthnStorage covers WebAuthn passkey credentials.
type WebAuthnStorage interface {
	MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID ULID) error
	InsertWebAuthnCredential(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error)
	WebAuthnCredentialsByUserID(ctx context.Context, userID ULID) ([]WebAuthnCredential, error)
	WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	// UpdateWebAuthnSignCount atomically writes a strictly greater sign count. It returns
	// ErrReplayDetected when the new count is not greater (the WebAuthn replay signal) and
	// ErrStorageNotFound for an unknown credential.
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error
	// UpdateWebAuthnBackupFlags is an idempotent trust-on-first-use write of the backup flags for
	// legacy passkeys. Return nil when the credential is missing: a failed reconciliation must never
	// fail an already-verified login.
	UpdateWebAuthnBackupFlags(ctx context.Context, credentialID []byte, backupEligible, backupState bool) error
	// DeleteWebAuthnCredential removes a credential scoped to its owner. It returns ErrStorageNotFound
	// for another user's credential, so cross-user lookups leak nothing.
	DeleteWebAuthnCredential(ctx context.Context, id ULID, userID ULID) error
}

// TOTPStorage covers TOTP secrets and recovery codes.
type TOTPStorage interface {
	// MoveTOTPSecret reassigns secondaryID's TOTP secret to primaryID. An existing confirmed primary
	// secret wins and the secondary is dropped, preserving the active factor.
	MoveTOTPSecret(ctx context.Context, primaryID, secondaryID ULID) error
	// UpsertPendingTOTPSecret writes an encrypted, unconfirmed secret. It preserves a confirmed secret
	// untouched; re-enrollment requires DeleteTOTPSecret first.
	UpsertPendingTOTPSecret(ctx context.Context, s TOTPSecret) error
	ConfirmTOTPSecret(ctx context.Context, userID ULID, at time.Time) error
	TOTPSecretByUserID(ctx context.Context, userID ULID) (*TOTPSecret, error)
	DeleteTOTPSecret(ctx context.Context, userID ULID) error

	InsertRecoveryCodes(ctx context.Context, codes []RecoveryCode) error
	// ConsumeRecoveryCode marks the matching unused code used, atomically. It returns
	// ErrStorageNotFound for a wrong, reused or cross-user code.
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

	ListUsersByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMUserFilter) (users []User, total int, err error)
	ListGroupsByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMGroupFilter) (groups []Group, total int, err error)
	UserByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*User, error)
	UpdateUserSCIM(ctx context.Context, u User) error

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
	// Permissions form a global catalog. Insert is idempotent on name, so seeding at app start is safe.
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
	PermissionsByRole(ctx context.Context, roleID ULID) ([]string, error)

	GrantUserRole(ctx context.Context, ur UserRole) error
	RevokeUserRole(ctx context.Context, userID, roleID ULID) error
	RolesForUser(ctx context.Context, userID ULID, orgID *ULID) ([]Role, error)
	PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error)
	CountUsersWithPermissionInOrg(ctx context.Context, orgID ULID, perm string) (int, error)
}

// AuditStorage covers the append-only audit log.
type AuditStorage interface {
	// InsertAuditEvents writes a batch in one round trip. The log is append-only: adapters must not
	// expose UPDATE or DELETE for audit rows. On failure the writer logs and increments
	// Stats.AuditFailed without retrying (a documented tradeoff).
	InsertAuditEvents(ctx context.Context, events []AuditEvent) error
	QueryAuditEvents(ctx context.Context, q AuditQuery) (events []AuditEvent, nextCursor string, err error)
}

// CoreStorage is the minimal capability set for email and password sign-in, sessions and magic
// links. Set it as Config.CoreStorage to skip the organization, SAML, SCIM, WebAuthn, TOTP and RBAC
// methods.
type CoreStorage interface {
	UserStorage
	SessionStorage
	MagicLinkStorage
	PasswordStorage
}

// ErrStorageMissingCapability is returned by New when an enabled feature needs a capability the
// storage lacks.
var ErrStorageMissingCapability = models.ErrStorageMissingCapability

func missingCapability(name string) error {
	return fmt.Errorf("%w: %s", ErrStorageMissingCapability, name)
}

// assembledStorage runs full-Storage services on a CoreStorage. Missing capabilities return
// ErrStorageMissingCapability; New has already rejected configs that enable them.
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

// TOTPReplayStorage is an optional capability making TOTP replay protection durable across
// processes. Without it the last used step is tracked in process memory only.
type TOTPReplayStorage interface {
	// AdvanceTOTPStep atomically records step as the last used time-step. It returns false and changes
	// nothing when step is not greater than the stored value.
	AdvanceTOTPStep(ctx context.Context, userID ULID, step int64) (advanced bool, err error)
}

// UserCountStorage is an optional capability required by Config.Bootstrap to detect whether the
// first administrator has been created yet.
type UserCountStorage interface {
	CountUsers(ctx context.Context) (int, error)
}

// WebAuthnRenameStorage is the optional capability behind passkey rename (PATCH
// /auth/webauthn/credentials/{id}).
type WebAuthnRenameStorage interface {
	RenameWebAuthnCredential(ctx context.Context, id, userID ULID, name string) error
}

// RecoveryCodeStorage is the optional capability behind GET /auth/totp (remaining recovery codes)
// and POST /auth/totp/recovery-codes.
type RecoveryCodeStorage interface {
	CountUnusedRecoveryCodes(ctx context.Context, userID ULID) (int, error)
	ReplaceRecoveryCodes(ctx context.Context, userID ULID, codes []RecoveryCode) error
}

// TOTPStatus reports whether TOTP is enrolled and how many recovery codes remain (-1 when the
// storage cannot count them).
type TOTPStatus = totp.Status

// TOTPStatus reports whether TOTP is enrolled and how many recovery codes remain (-1 when the
// storage cannot count them).
func (a *TheAuth) TOTPStatus(ctx context.Context, userID ULID) (TOTPStatus, error) {
	return a.totpSvc.Status(ctx, userID)
}

// RegenerateRecoveryCodes replaces the user's recovery codes and returns the new plaintext codes once.
func (a *TheAuth) RegenerateRecoveryCodes(ctx context.Context, userID ULID) ([]string, error) {
	return a.totpSvc.RegenerateRecoveryCodes(ctx, userID)
}

// RenamePasskey changes the display name of one of the user's passkeys.
func (a *TheAuth) RenamePasskey(ctx context.Context, id, userID ULID, name string) error {
	return a.webauthnSvc.RenameCredential(ctx, id, userID, name)
}

// SessionLink is a short-lived, single-use grant that exchanges for a session.
type SessionLink = models.SessionLink

// SessionManagementStorage is the optional capability behind session lists, idle timeout, last-seen
// tracking and step-up. It is detected by type assertion and is not part of Storage.
type SessionManagementStorage interface {
	ListUserSessions(ctx context.Context, userID ULID) ([]Session, error)
	TouchSession(ctx context.Context, id ULID, at time.Time) error
	RevokeOtherUserSessions(ctx context.Context, userID, keep ULID) (int, error)
	RevokeSessionsByCredential(ctx context.Context, credentialID string) (int, error)
	SetSessionElevatedUntil(ctx context.Context, id ULID, until *time.Time) error
}

// SessionAuthStorage is the optional capability that atomically records a second factor or step-up
// in a session's auth methods. Built-in backends persist AuthMethods and AuthTime on CreateSession
// already; without this interface sessions simply carry no appended record.
type SessionAuthStorage interface {
	// AppendSessionAuthMethods adds missing methods (order kept, no duplicates) and advances AuthTime
	// to at when later.
	AppendSessionAuthMethods(ctx context.Context, id ULID, methods []string, at time.Time) ([]string, time.Time, error)
}

// SessionLinkStorage is the optional capability behind programmatic session links.
type SessionLinkStorage interface {
	CreateSessionLink(ctx context.Context, l SessionLink) error
	ConsumeSessionLink(ctx context.Context, tokenHash []byte, now time.Time) (*SessionLink, error)
}

// ErrImportDuplicate is returned by the Import helpers when the record already exists; callers may
// treat it as already imported.
var ErrImportDuplicate = models.ErrImportDuplicate

// ErrImportInvalid wraps every Import helper validation failure.
var ErrImportInvalid = importer.ErrImportInvalid

// ImportUserStorage is the storage surface ImportUserTo needs.
type ImportUserStorage interface {
	UserStorage
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
}

// ImportedUser is an existing account to insert.
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

// ImportTOTPSecretTo encrypts the plaintext secret with encryptionKey and stores it as confirmed,
// with no TheAuth instance.
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

// ImportTOTPSecret encrypts a plaintext secret with Config.EncryptionKey and stores it as
// confirmed; see ImportTOTPSecretTo.
func (a *TheAuth) ImportTOTPSecret(ctx context.Context, in ImportedTOTP) error {
	return ImportTOTPSecretTo(ctx, a.storage, a.encryptionKey, in)
}

// ImportWebAuthnCredential inserts an existing credential through the configured storage; see
// ImportWebAuthnCredentialTo.
func (a *TheAuth) ImportWebAuthnCredential(ctx context.Context, in ImportedWebAuthnCredential) (WebAuthnCredential, error) {
	return ImportWebAuthnCredentialTo(ctx, a.storage, in)
}

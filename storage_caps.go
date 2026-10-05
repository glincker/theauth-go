package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

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
		OAuthAccountStorage: unsupportedOAuthAccountStorage{},
		WebAuthnStorage:     unsupportedWebAuthnStorage{},
		TOTPStorage:         unsupportedTOTPStorage{},
		OrganizationStorage: unsupportedOrganizationStorage{},
		SAMLStorage:         unsupportedSAMLStorage{},
		SCIMStorage:         unsupportedSCIMStorage{},
		RBACStorage:         unsupportedRBACStorage{},
		AuditStorage:        unsupportedAuditStorage{},
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

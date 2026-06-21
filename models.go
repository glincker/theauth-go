package theauth

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID is the canonical ID type — generated in app, stored as uuid in Postgres.
type ULID = ulid.ULID

type User struct {
	ID              ULID       `json:"id"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	Name            string     `json:"name"`
	AvatarURL       string     `json:"avatarUrl"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	// ExternalID (v0.7 SCIM) stores the SCIM client's stable identifier so
	// upsert by externalId works. Empty for users not created via SCIM.
	ExternalID string `json:"externalId,omitempty"`
	// GivenName / FamilyName / DisplayName (v0.7 SCIM) capture the structured
	// name attributes SCIM clients provision; they are best-effort projections
	// alongside Name and may be empty for users created via other flows.
	GivenName   string `json:"givenName,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// Session auth levels (v0.5). AuthLevelFull is the post-MFA, full-access
// state. AuthLevelPending2FA is the short-lived state after a successful
// password verify on an account that also has TOTP enrolled: the user has
// proven the first factor and may only call /auth/totp/verify or
// /auth/totp/recovery. RequireAuth rejects pending sessions everywhere else.
const (
	AuthLevelFull       = "full"
	AuthLevelPending2FA = "pending_2fa"
)

type Session struct {
	ID        ULID       `json:"id"`
	UserID    ULID       `json:"userId"`
	TokenHash []byte     `json:"-"` // never serialize raw hash
	UserAgent string     `json:"userAgent"`
	IP        string     `json:"ip"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// AuthLevel is "full" or "pending_2fa" (v0.5). Sessions issued by code
	// paths predating v0.5 default to "full" so existing rows keep working.
	AuthLevel string `json:"authLevel,omitempty"`
	// ActiveOrganizationID (v0.7) scopes a session to one organization for
	// the duration of the session. Nil in single-tenant deployments and on
	// any session that has not picked an org yet.
	ActiveOrganizationID *ULID `json:"activeOrganizationId,omitempty"`
}

// Expired reports whether the session is no longer usable at the given time.
func (s Session) Expired(now time.Time) bool {
	if s.RevokedAt != nil {
		return true
	}
	return !now.Before(s.ExpiresAt)
}

type MagicLink struct {
	ID        ULID       `json:"id"`
	Email     string     `json:"email"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// PasswordResetToken backs the /auth/email-password/forgot+reset flow. Shape
// mirrors MagicLink but binds to a known user_id (resets always operate on an
// existing account), and lives in its own table to keep flows isolated.
type PasswordResetToken struct {
	ID        ULID       `json:"id"`
	UserID    ULID       `json:"userId"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// OAuthAccount records the linkage between one of our Users and a remote
// OAuth provider identity (e.g. user X authenticates via GitHub). The
// (provider, provider_user_id) pair is unique; re-running the OAuth flow
// for the same provider account upserts this row rather than creating a
// duplicate. Tokens are encrypted at rest via crypto.Encrypt and are
// never serialized over JSON.
type OAuthAccount struct {
	ID              ULID       `json:"id"`
	UserID          ULID       `json:"userId"`
	Provider        string     `json:"provider"`
	ProviderUserID  string     `json:"providerUserId"`
	AccessTokenEnc  []byte     `json:"-"`
	RefreshTokenEnc []byte     `json:"-"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	Scope           string     `json:"scope"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// WebAuthnCredential mirrors the persistent subset of webauthn.Credential.
// We store the COSE-encoded public key plus the metadata we own (nickname,
// timestamps, sign count). One row per registered authenticator; the same
// user can register many. CredentialID is the raw byte string the
// authenticator returned at registration and must be globally unique to
// prevent a stolen credential being re-registered against a different user.
//
// SignCount is monotonic per credential. A login that supplies a non-greater
// value than the stored count is treated as a clone-attempt and refused via
// ErrReplayDetected (carve-out: an authenticator that never implements sign
// counts always returns 0, which the library handles as a per-spec exception).
type WebAuthnCredential struct {
	ID           ULID       `json:"id"`
	UserID       ULID       `json:"userId"`
	CredentialID []byte     `json:"credentialId"`
	PublicKey    []byte     `json:"-"`
	SignCount    uint32     `json:"signCount"`
	Transports   []string   `json:"transports"`
	AAGUID       []byte     `json:"aaguid"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
}

// TOTPSecret stores the AES-GCM encrypted shared secret for one user. The
// secret is base32 plaintext only at enroll-begin and verify time; on disk
// it is always ciphertext (nonce prepended, courtesy of crypto.Encrypt).
// ConfirmedAt is NULL until the user proves possession by entering one
// valid code in /auth/totp/enroll/finish. Unconfirmed rows are overwritten
// by a subsequent /enroll/begin (no half-state can survive).
type TOTPSecret struct {
	UserID      ULID       `json:"userId"`
	SecretEnc   []byte     `json:"-"`
	ConfirmedAt *time.Time `json:"confirmedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// RecoveryCode is one of N single-use codes generated at TOTP enrollment.
// CodeHash carries the 16-byte salt prefix followed by sha256(salt || code),
// produced by crypto.HashRecoveryCode. UsedAt is set the first time a user
// consumes the code; the same hash cannot be replayed.
type RecoveryCode struct {
	ID        ULID       `json:"id"`
	UserID    ULID       `json:"userId"`
	CodeHash  []byte     `json:"-"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// ---------- v0.7 multi-tenancy + SAML + SCIM ----------

// Organization role constants. Scoped to one organization each.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Organization is the top-level multi-tenant container. Slug is a citext
// unique URL-safe handle (lowercased on write).
type Organization struct {
	ID        ULID      `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// OrganizationMember binds a user to an organization with a single role.
// Role values: "owner", "admin", "member". owner can manage SAML and SCIM,
// admin can manage SCIM only, member is read-only against org metadata.
type OrganizationMember struct {
	OrganizationID ULID      `json:"organizationId"`
	UserID         ULID      `json:"userId"`
	Role           string    `json:"role"`
	JoinedAt       time.Time `json:"joinedAt"`
}

// SAMLAttributeMap projects SAML attribute names to canonical user fields.
// Stored as jsonb in saml_connections.attribute_map.
type SAMLAttributeMap struct {
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	GivenName  string            `json:"givenName,omitempty"`
	FamilyName string            `json:"familyName,omitempty"`
	Groups     string            `json:"groups,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// DefaultSAMLAttributeMap returns the WS-Federation claim URIs that Microsoft,
// Okta, and OneLogin emit by default. A per-connection map can override any
// of these by writing a non-empty string for the field.
func DefaultSAMLAttributeMap() SAMLAttributeMap {
	return SAMLAttributeMap{
		Email:      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		Name:       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		GivenName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		FamilyName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		Groups:     "http://schemas.xmlsoap.org/claims/Group",
	}
}

// SAMLConnection is one IdP binding for one organization. An organization can
// hold multiple connections (e.g. two distinct Okta tenants for subsidiaries),
// each routed by id in the URL.
type SAMLConnection struct {
	ID             ULID             `json:"id"`
	OrganizationID ULID             `json:"organizationId"`
	IdPEntityID    string           `json:"idpEntityId"`
	IdPSSOURL      string           `json:"idpSsoUrl"`
	IdPX509Cert    string           `json:"idpX509Cert"`
	SPEntityID     string           `json:"spEntityId"`
	SPACSURL       string           `json:"spAcsUrl"`
	AttributeMap   SAMLAttributeMap `json:"attributeMap"`
	CreatedAt      time.Time        `json:"createdAt"`
	UpdatedAt      time.Time        `json:"updatedAt"`
}

// SAMLIdentity links a successful SAML login to a user. Lookup key is
// (connection_id, name_id); name_id is whatever Subject.NameID.Value the IdP
// emitted, opaque and stable across sessions for most IdPs.
type SAMLIdentity struct {
	ID           ULID       `json:"id"`
	ConnectionID ULID       `json:"connectionId"`
	UserID       ULID       `json:"userId"`
	NameID       string     `json:"nameId"`
	NameIDFormat string     `json:"nameIdFormat"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// SCIMToken is a hashed bearer token bound to one organization. Plaintext is
// only ever returned from CreateSCIMToken; subsequent reads only ever see the
// hash. Hash is sha256(token); rationale documented in the v0.7 spec.
type SCIMToken struct {
	ID             ULID       `json:"id"`
	OrganizationID ULID       `json:"organizationId"`
	Name           string     `json:"name"`
	TokenHash      []byte     `json:"-"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

// Group is a SCIM-first concept. v0.7 stores them flat (no nesting), scoped
// to one organization. Application semantics (mapping a group to a role) land
// in v0.8 RBAC.
type Group struct {
	ID             ULID      `json:"id"`
	OrganizationID ULID      `json:"organizationId"`
	DisplayName    string    `json:"displayName"`
	ExternalID     string    `json:"externalId,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// SCIMUserFilter is the equality-only filter accepted on /scim/v2/Users.
// Anything outside this whitelist returns 400 invalidFilter.
type SCIMUserFilter struct {
	UserName   string
	ExternalID string
	Email      string
}

// SCIMGroupFilter is the equality-only filter accepted on /scim/v2/Groups.
type SCIMGroupFilter struct {
	DisplayName string
	ExternalID  string
}

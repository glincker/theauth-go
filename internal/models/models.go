package models

import (
	"errors"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID is the canonical ID type, generated in app, stored as uuid in Postgres.
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
	// LastSeenAt is the throttled last-activity time used for idle timeout
	// and the "last seen" column of a session list. Zero on rows written by
	// storage without SessionManagementStorage.
	LastSeenAt time.Time `json:"lastSeenAt"`
	// ElevatedUntil marks a step-up re-authentication window; nil when the
	// session was never elevated.
	ElevatedUntil *time.Time `json:"elevatedUntil,omitempty"`
	// CredentialID names the upstream credential (for example an API token
	// id) a session minted from a session link is tied to; empty otherwise.
	CredentialID string `json:"credentialId,omitempty"`
	// AuthMethods lists the RFC 8176 authentication method references the
	// session proved so far, in the order they were proved (for example
	// ["pwd","otp","mfa"]). Nil on sessions created before the record
	// existed or by a storage without SessionAuthStorage; see AMR* constants.
	AuthMethods []string `json:"authMethods,omitempty"`
	// AuthTime is when the user last proved identity with a method in
	// AuthMethods: sign-in time, advanced by every second factor or step-up.
	// The zero time on sessions without an AuthMethods record.
	AuthTime time.Time `json:"authTime,omitempty"`
}

// RFC 8176 authentication method references recorded on a session. The
// registered values are pwd, otp, hwk, swk and mfa. AMREmail, AMRFederated
// and AMRSSO are theauth specific values for flows RFC 8176 has no name for;
// they are never confused with the registered ones.
const (
	// AMRPassword is a password sign-in or password step-up.
	AMRPassword = "pwd"
	// AMROTP is a one-time code: TOTP or a recovery code.
	AMROTP = "otp"
	// AMRHardwareKey is a passkey bound to one authenticator (hwk): the
	// credential is not backup eligible.
	AMRHardwareKey = "hwk"
	// AMRSoftwareKey is a synced, backup eligible passkey (swk): its key lives
	// in a credential manager, not in a single device.
	AMRSoftwareKey = "swk"
	// AMRUserVerified marks that the authenticator reported user verification
	// (PIN or biometric) for a passkey assertion ("user", RFC 8176 section 2).
	AMRUserVerified = "user"
	// AMRMFA marks that two or more distinct factors were proved.
	AMRMFA = "mfa"
	// AMREmail is a magic link or emailed code sign-in (not RFC 8176).
	AMREmail = "email"
	// AMRFederated is a social OAuth sign-in (not RFC 8176).
	AMRFederated = "fed"
	// AMRSSO is an enterprise SAML sign-in (not RFC 8176).
	AMRSSO = "sso"
)

// HasMethod reports whether the session recorded the authentication method m
// (case-insensitive). False for sessions without a record.
func (s Session) HasMethod(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	for _, have := range s.AuthMethods {
		if strings.ToLower(have) == m {
			return true
		}
	}
	return false
}

// HasAnyMethod reports whether the session recorded at least one of methods.
func (s Session) HasAnyMethod(methods ...string) bool {
	for _, m := range methods {
		if s.HasMethod(m) {
			return true
		}
	}
	return false
}

// HasAllMethods reports whether the session recorded every one of methods.
func (s Session) HasAllMethods(methods ...string) bool {
	for _, m := range methods {
		if !s.HasMethod(m) {
			return false
		}
	}
	return true
}

// MergeAuthMethods returns existing followed by the entries of add that are
// not yet present, normalized to lower case with blanks dropped. It never
// reorders existing entries.
func MergeAuthMethods(existing []string, add ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(add))
	out := make([]string, 0, len(existing)+len(add))
	for _, list := range [][]string{existing, add} {
		for _, m := range list {
			m = strings.ToLower(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			if _, dup := seen[m]; dup {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out
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
	// BackupEligible / BackupState mirror the WebAuthn BE / BS authenticator
	// flags (a "backup eligible" credential is a synced passkey: iCloud
	// Keychain, Google Password Manager, etc.). go-webauthn's login
	// validation rejects an assertion whose BE flag differs from the stored
	// credential, so these MUST round-trip or every synced passkey login
	// fails. They are pointers on purpose: nil means "never recorded" (a
	// credential registered before this column existed) which the login path
	// reconciles via trust-on-first-use, and is distinct from a non-nil
	// false (a genuine non-backup-eligible credential recorded after the fix).
	BackupEligible *bool `json:"backupEligible,omitempty"`
	BackupState    *bool `json:"backupState,omitempty"`
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

// v0.7 multi-tenancy + SAML + SCIM

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

// v1.0 RBAC

// Permission is one entry in the closed permission catalog. Names are program
// identifiers (ASCII, no whitespace) of the shape "domain:verb" or
// "domain:verb:scope". Seeded permissions live in service_rbac.go.
type Permission struct {
	ID          ULID      `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Role binds a permission set to an organization (or to the global namespace
// when OrganizationID is nil, i.e. system roles such as super_admin).
// Permissions is the hydrated permission-name slice and is not persisted on
// the Role row itself; storage adapters fill it on read via
// PermissionsByRole.
type Role struct {
	ID             ULID      `json:"id"`
	OrganizationID *ULID     `json:"organizationId,omitempty"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Permissions    []string  `json:"permissions"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// UserRole records a grant of one role to one user. GrantedBy is the actor
// that issued the grant; nil indicates a system grant (e.g. seeded by
// SeedOrganizationRoles itself).
type UserRole struct {
	UserID    ULID      `json:"userId"`
	RoleID    ULID      `json:"roleId"`
	GrantedAt time.Time `json:"grantedAt"`
	GrantedBy *ULID     `json:"grantedBy,omitempty"`
}

// SystemRoleSuperAdmin is the global role whose presence on a user bypasses
// every permission check. It is created at seed time with a NULL
// organization_id and is granted via direct DB insert or a CLI; the admin
// API never exposes a path to grant it.
const SystemRoleSuperAdmin = "super_admin"

// v1.0 audit log

// TargetRef points at the resource an audit event acts on. ID is a string
// (not ULID) because some targets are external identifiers (e.g. SCIM
// externalId) rather than ULIDs.
type TargetRef struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}

// AuditEvent is one append-only row in audit_events. Metadata is arbitrary
// jsonb; the default redactor masks secret-flavored keys at any depth before
// the value reaches storage.
type AuditEvent struct {
	ID             ULID           `json:"id"`
	OrganizationID *ULID          `json:"organizationId,omitempty"`
	ActorUserID    *ULID          `json:"actorUserId,omitempty"`
	ActorSessionID *ULID          `json:"actorSessionId,omitempty"`
	Action         string         `json:"action"`
	TargetType     string         `json:"targetType,omitempty"`
	TargetID       string         `json:"targetId,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	IP             string         `json:"ip,omitempty"`
	UserAgent      string         `json:"userAgent,omitempty"`
	CreatedAt      time.Time      `json:"createdAt"`

	// Event is the shared event name (see internal/audit events and the audit package), empty when
	// the writer did not set one or the action has no shared name (stored as NULL). RecordedAtUs is
	// the microsecond write-order stamp assigned by the store inside the append, strictly increasing
	// per chain key, zero on rows from stores or schemas that predate it. Neither field is part of
	// the audit chain hash, and a value passed to InsertAuditEvents for RecordedAtUs is ignored.
	Event        string `json:"event,omitempty"`
	RecordedAtUs int64  `json:"recordedAtUs,omitempty"`

	// Accountability fields. SubjectID is the principal the action was taken
	// on behalf of; ActorID is the agent or service that performed it. Token
	// `sub` semantics are unchanged: these are recorded explicitly instead.
	SubjectID       string         `json:"subjectId,omitempty"`
	ActorID         string         `json:"actorId,omitempty"`
	PolicyVersion   string         `json:"policyVersion,omitempty"`
	ApproverID      string         `json:"approverId,omitempty"`
	DelegationChain []string       `json:"delegationChain,omitempty"`
	InputProvenance map[string]any `json:"inputProvenance,omitempty"`

	// Hash chain output, set by stores that chain (sqlite, postgres, mysql). ChainSeq counts
	// up from 1 per chain key (the organization id, or empty). Zero Hash
	// means the row is not chained.
	ChainSeq uint64 `json:"chainSeq,omitempty"`
	PrevHash string `json:"prevHash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// AuditChainBreak describes the first row at which an audit chain fails to verify.
type AuditChainBreak struct {
	ChainKey string `json:"chainKey"`
	RowID    string `json:"rowId"`
	Seq      int64  `json:"seq"`
	// Reason is one of hash_mismatch, prev_hash_mismatch, seq_gap,
	// pseudonym_mismatch (a raw id column was edited after the row was written).
	// On postgres and mysql, hash_mismatch also covers a native jsonb/inet or
	// foreign key column that disagrees with the hashed text.
	Reason string `json:"reason"`
}

// AuditChainResult is the outcome of verifying an audit store's hash chain.
//
// Supported is false for backends that keep no chain (memory, postgres,
// mysql). In that case OK is also false and nothing was checked: callers must
// treat the result as "not tamper-evident", never as a pass.
type AuditChainResult struct {
	Supported bool `json:"supported"`
	OK        bool `json:"ok"`
	// Checked is the number of chained rows examined.
	Checked int `json:"checked"`
	// Unchained is the number of rows written before the chain existed.
	Unchained int `json:"unchained"`
	// Erased is the number of checked rows whose raw actor ids were erased
	// (GDPR). They still verify through their stored pseudonym.
	Erased int `json:"erased"`
	// FirstBreak is set when a supported chain fails to verify.
	FirstBreak *AuditChainBreak `json:"firstBreak,omitempty"`
}

// ErrAuditChainUnsupported is returned alongside an unsupported
// AuditChainResult when verification is requested on a backend without a chain.
var ErrAuditChainUnsupported = errors.New("audit chain verification is not supported by this storage backend")

// AccountabilityMetadataKey is the reserved metadata key under which stores
// without native accountability columns keep these fields.
const AccountabilityMetadataKey = "_accountability"

// HasAccountability reports whether any accountability field is set.
func (e AuditEvent) HasAccountability() bool {
	return e.SubjectID != "" || e.ActorID != "" || e.PolicyVersion != "" || e.ApproverID != "" ||
		len(e.DelegationChain) > 0 || len(e.InputProvenance) > 0
}

// MetadataWithAccountability returns Metadata with the accountability fields
// folded in under AccountabilityMetadataKey. The input map is not modified.
// Stores without native columns persist this value so the fields are not lost.
func (e AuditEvent) MetadataWithAccountability() map[string]any {
	if !e.HasAccountability() {
		return e.Metadata
	}
	out := make(map[string]any, len(e.Metadata)+1)
	for k, v := range e.Metadata {
		out[k] = v
	}
	acc := map[string]any{}
	if e.SubjectID != "" {
		acc["subjectId"] = e.SubjectID
	}
	if e.ActorID != "" {
		acc["actorId"] = e.ActorID
	}
	if e.PolicyVersion != "" {
		acc["policyVersion"] = e.PolicyVersion
	}
	if e.ApproverID != "" {
		acc["approverId"] = e.ApproverID
	}
	if len(e.DelegationChain) > 0 {
		acc["delegationChain"] = e.DelegationChain
	}
	if len(e.InputProvenance) > 0 {
		acc["inputProvenance"] = e.InputProvenance
	}
	out[AccountabilityMetadataKey] = acc
	return out
}

// AuditQuery filters and paginates audit_events reads. Zero-valued fields
// are ignored. Limit is capped at 200 and defaults to 50; After is the
// opaque cursor returned by the previous page.
//
// Event keeps only rows whose event equals it. Order is AuditOrderDesc (the default, newest
// write first) or AuditOrderAsc, and applies to stores that declare write order support. A
// cursor is only valid for the order that produced it. Cursors from before write order existed
// (no "c1." prefix) keep working for descending reads.
type AuditQuery struct {
	OrganizationID *ULID
	ActorUserID    *ULID
	Action         string
	TargetType     string
	TargetID       string
	Since          *time.Time
	Until          *time.Time
	Event          string
	// Provenance keeps rows that recorded a given input source. Needs a backend that declares
	// AuditProvenanceSupported() true, otherwise the query fails with ErrAuditProvenanceUnsupported.
	Provenance *ProvenanceFilter
	Order      string
	Limit      int
	After      string
}

// ProvenanceFilter narrows an audit query by input provenance. Both fields narrow the match.
type ProvenanceFilter struct {
	// Kind is user_message, tool_output, retrieved_document or agent.
	Kind string
	// Hash is 64 lowercase hex characters, from the input hasher (audit.InputHasher.Hash).
	Hash string
}

// Audit read orders for AuditQuery.Order. The empty value means AuditOrderDesc.
const (
	AuditOrderAsc  = "asc"
	AuditOrderDesc = "desc"
)

// Stats holds runtime counters useful for ops dashboards and tests. Counters
// are monotonically non-decreasing; reads are atomic snapshots. AuditFailed
// counts batches whose INSERT returned an error; the writer goroutine logs
// the error and does not retry (the v1.0 tradeoff documented in
// AuditSinkFailed counts individual sink Stream errors across all registered
// sinks; incremented once per failing sink per batch (not per event).
type Stats struct {
	AuditEmitted    uint64 `json:"auditEmitted"`
	AuditWritten    uint64 `json:"auditWritten"`
	AuditDropped    uint64 `json:"auditDropped"`
	AuditFailed     uint64 `json:"auditFailed"`
	AuditSinkFailed uint64 `json:"auditSinkFailed"`
}

package theauth

// Type, constant, and function aliases that re-export the v0.x model layer
// (User, Session, MagicLink, organization + SAML + SCIM + RBAC + audit
// structs) from the canonical internal home at
// github.com/glincker/theauth-go/internal/models.
//
// The alias form (type X = models.X, const X = models.X, var X = models.X)
// preserves COMPILE-TIME API stability: every exported symbol in this file
// has the same identity, method set, and signature as the underlying
// internal/models declaration, so downstream consumers cannot tell the
// difference at compile time. This pattern is used by chi
// (go-chi/chi/v5 re-exports middleware), oauth2 (golang.org/x/oauth2
// re-exports endpoint), and go-kit (github.com/go-kit/kit re-exports
// transport types) and is the idiomatic Go answer to "I want the
// package layout I want without breaking the API I shipped."
//
// pkg.go.dev renders alias destinations as links to the underlying type
// docs (in internal/models here, which pkg.go.dev still indexes for the
// docstring even though it is not importable). godoc CLI output renders
// the alias line itself instead of the underlying type body; this is
// expected and is no longer a STABILITY check.

import "github.com/glincker/theauth-go/internal/models"

// ---------- v0.x core entity types ----------

// ULID is the canonical ID type, generated in app, stored as uuid in Postgres.
type ULID = models.ULID

type User = models.User

type Session = models.Session

type MagicLink = models.MagicLink

// PasswordResetToken backs the /auth/email-password/forgot+reset flow.
type PasswordResetToken = models.PasswordResetToken

type OAuthAccount = models.OAuthAccount

type WebAuthnCredential = models.WebAuthnCredential

type TOTPSecret = models.TOTPSecret

type RecoveryCode = models.RecoveryCode

// ---------- v0.5 session auth-level constants ----------

const (
	AuthLevelFull       = models.AuthLevelFull
	AuthLevelPending2FA = models.AuthLevelPending2FA
)

// ---------- v0.7 multi-tenancy + SAML + SCIM ----------

const (
	OrgRoleOwner  = models.OrgRoleOwner
	OrgRoleAdmin  = models.OrgRoleAdmin
	OrgRoleMember = models.OrgRoleMember
)

type Organization = models.Organization

type OrganizationMember = models.OrganizationMember

type SAMLAttributeMap = models.SAMLAttributeMap

// DefaultSAMLAttributeMap returns the WS-Federation claim URIs that
// Microsoft, Okta, and OneLogin emit by default.
var DefaultSAMLAttributeMap = models.DefaultSAMLAttributeMap

type SAMLConnection = models.SAMLConnection

type SAMLIdentity = models.SAMLIdentity

type SCIMToken = models.SCIMToken

type Group = models.Group

type SCIMUserFilter = models.SCIMUserFilter

type SCIMGroupFilter = models.SCIMGroupFilter

// ---------- v1.0 RBAC + audit ----------

type Permission = models.Permission

type Role = models.Role

type UserRole = models.UserRole

// SystemRoleSuperAdmin is the global role whose presence on a user bypasses
// every permission check.
const SystemRoleSuperAdmin = models.SystemRoleSuperAdmin

type TargetRef = models.TargetRef

type AuditEvent = models.AuditEvent

type AuditQuery = models.AuditQuery

type Stats = models.Stats

// ---------- v2.0 OAuth 2.1 AS primitives (merged from models_v20.go in PR G) ----------

type ClientOwner = models.ClientOwner

type OAuthClient = models.OAuthClient

type AuthorizationCode = models.AuthorizationCode

type RefreshToken = models.RefreshToken

type JWKSKey = models.JWKSKey

// JWKS key state constants.
const (
	JWKSStateNext     = models.JWKSStateNext
	JWKSStateCurrent  = models.JWKSStateCurrent
	JWKSStatePrevious = models.JWKSStatePrevious
	JWKSStateRetired  = models.JWKSStateRetired
)

// Client owner kind constants persisted in oauth_clients.owner_kind.
const (
	ClientOwnerKindUser         = models.ClientOwnerKindUser
	ClientOwnerKindOrganization = models.ClientOwnerKindOrganization
	ClientOwnerKindAgent        = models.ClientOwnerKindAgent
	ClientOwnerKindAnonymous    = models.ClientOwnerKindAnonymous
)

// Client authentication method constants.
const (
	ClientAuthSecretBasic = models.ClientAuthSecretBasic
	ClientAuthSecretPost  = models.ClientAuthSecretPost
	ClientAuthNone        = models.ClientAuthNone
)

// Grant type constants.
const (
	GrantTypeAuthorizationCode = models.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = models.GrantTypeRefreshToken
	GrantTypeClientCredentials = models.GrantTypeClientCredentials
	GrantTypeTokenExchange     = models.GrantTypeTokenExchange
)

// Token type URNs used by the RFC 8693 token-exchange grant.
const (
	TokenTypeAccessToken = models.TokenTypeAccessToken
)

// Response type constants. OAuth 2.1 supports only "code".
const (
	ResponseTypeCode = models.ResponseTypeCode
)

// ---------- v2.0 phase 3 agent identity ----------

type AgentOwner = models.AgentOwner

type CreateAgentInput = models.CreateAgentInput

// Agent lifecycle status values persisted in agents.status.
const (
	AgentStatusActive    = models.AgentStatusActive
	AgentStatusSuspended = models.AgentStatusSuspended
	AgentStatusRevoked   = models.AgentStatusRevoked
)

// Agent credential kind constants persisted in agent_credentials.kind.
const (
	AgentCredentialKindSecret = models.AgentCredentialKindSecret
	AgentCredentialKindX509   = models.AgentCredentialKindX509
	AgentCredentialKindJWK    = models.AgentCredentialKindJWK
)

// AgentSubjectPrefix is prepended to an agent ID inside JWT sub and act.sub
// claims so resource servers can distinguish a user subject from an agent
// subject without consulting storage.
const AgentSubjectPrefix = models.AgentSubjectPrefix

type Agent = models.Agent

type AgentCredential = models.AgentCredential

type AgentSecret = models.AgentSecret

// ---------- v2.0 phase 4 delegation ----------

type DelegationGrant = models.DelegationGrant

type GrantDelegationInput = models.GrantDelegationInput

type ActorClaim = models.ActorClaim

// ---------- v2.0 resource + DCR types ----------

// ProtectedResource describes one resource server protected by this AS.
type ProtectedResource = models.ProtectedResource

// RegisteredClient is the JSON body returned on a successful registration
// (RFC 7591 section 3.2.1).
type RegisteredClient = models.RegisteredClient

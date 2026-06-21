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

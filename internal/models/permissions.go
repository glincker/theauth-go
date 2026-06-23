package models

// Seeded permission catalog. Every consumer's permission set extends (never
// shrinks) this list; New returns an error if a custom Permission name
// duplicates a seeded one with a different description (defensive against
// silent overrides).
//
// The list is intentionally finite and small. Wildcards and ABAC are
// deferred to v1.x per the v1.0 design document.
const (
	PermissionBillingRead    = "billing:read"
	PermissionBillingWrite   = "billing:write"
	PermissionBillingAdmin   = "billing:admin"
	PermissionUsersRead      = "users:read"
	PermissionUsersInvite    = "users:invite"
	PermissionUsersAdmin     = "users:admin"
	PermissionRolesRead      = "roles:read"
	PermissionRolesAdmin     = "roles:admin"
	PermissionAuditRead      = "audit:read"
	PermissionSAMLAdmin      = "saml:admin"
	PermissionSCIMAdmin      = "scim:admin"
	PermissionSessionsRevoke = "sessions:revoke"

	// v2.0 phase 6 additions. agents:admin grants organization-scoped
	// agent CRUD via /admin/v1/.../agents; delegations:admin grants
	// delegation CRUD via /admin/v1/.../delegations. Seeded into every
	// organization's "owner" and "admin" default roles.
	PermissionAgentsAdmin      = "agents:admin"
	PermissionDelegationsAdmin = "delegations:admin"

	// v2.3 identity linking additions.
	// account:link allows the caller to link or unlink OAuth providers
	// and password credentials to their own account.
	PermissionAccountLink = "account:link"
	// account:merge allows the caller to initiate a destructive merge of
	// a secondary user record into their own (primary) account.
	PermissionAccountMerge = "account:merge"
)

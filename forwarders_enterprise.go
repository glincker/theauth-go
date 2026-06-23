package theauth

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/internal/organizations"
	internalscim "github.com/glincker/theauth-go/internal/scim"
)

// forwarders_enterprise.go consolidates the v0.7 - v1.0 enterprise
// forwarders (SCIM tokens, organizations + membership, RBAC, agent
// delegations) into a single file. PR G (2026-06-21) merged the previous
// service_scim.go, service_organizations.go, service_rbac.go, and
// service_delegation.go files here. Every method below is a one-line
// thunk over the matching internal/<flow>.Service; the substantive
// implementations live in those packages. No behaviour change;
// signatures are byte-stable with the v2.0 release.

// ---------- SCIM tokens ----------

// CreateSCIMToken mints a fresh 256-bit token, stores its sha256 hash,
// and returns the plaintext to the caller. The plaintext is the only
// point at which it leaves the library; subsequent reads only ever see
// the hash. Forwards to scimSvc.CreateToken, mapping
// internalscim.ErrSCIMDisabled to the legacy root error string.
func (a *TheAuth) CreateSCIMToken(ctx context.Context, orgID ULID, name string) (string, SCIMToken, error) {
	token, rec, err := a.scimSvc.CreateToken(ctx, orgID, name)
	if errors.Is(err, internalscim.ErrSCIMDisabled) {
		return "", SCIMToken{}, errors.New("theauth: SCIM not enabled")
	}
	return token, rec, err
}

// RevokeSCIMToken marks the named token as revoked. Revoked tokens still
// resolve via SCIMTokenByHash but the middleware refuses them. Forwards
// to scimSvc.RevokeToken.
func (a *TheAuth) RevokeSCIMToken(ctx context.Context, id ULID) error {
	return a.scimSvc.RevokeToken(ctx, id)
}

// ListSCIMTokens returns every token (revoked or not) for the supplied
// org. Forwards to scimSvc.ListTokens.
func (a *TheAuth) ListSCIMTokens(ctx context.Context, orgID ULID) ([]SCIMToken, error) {
	return a.scimSvc.ListTokens(ctx, orgID)
}

// SCIMAuthResult is the value returned by AuthenticateSCIMToken. Bundling
// OrgID and TokenID avoids the second SCIMTokenByHash storage call the
// middleware previously performed after a successful authentication
// (perf re-audit 2026-06-21, item 1).
type SCIMAuthResult struct {
	OrgID   ULID
	TokenID ULID
}

// AuthenticateSCIMToken is the entry point invoked by the SCIM bearer
// middleware on every request. Returns OrgID + TokenID in a single
// storage round-trip, or an error on failure. Touches last_used_at
// asynchronously on success. Forwards to scimSvc.Authenticate.
func (a *TheAuth) AuthenticateSCIMToken(ctx context.Context, presented string) (SCIMAuthResult, error) {
	res, err := a.scimSvc.Authenticate(ctx, presented)
	if err != nil {
		return SCIMAuthResult{}, err
	}
	return SCIMAuthResult{OrgID: res.OrganizationID, TokenID: res.TokenID}, nil
}

// ---------- Organizations + membership ----------

// CreateOrganization writes a new org row and adds the supplied user as
// its owner. Slug is lowercased and validated against the slug rules in
// the internal package; the storage layer enforces uniqueness. Forwards
// to orgsSvc.Create, mapping organizations.ErrOrganizationsDisabled to
// the legacy root error string.
func (a *TheAuth) CreateOrganization(ctx context.Context, name, slug string, ownerUserID ULID) (Organization, error) {
	org, err := a.orgsSvc.Create(ctx, name, slug, ownerUserID)
	if errors.Is(err, organizations.ErrOrganizationsDisabled) {
		return Organization{}, errors.New("theauth: organizations not enabled")
	}
	return org, err
}

// OrganizationBySlug looks up an organization by URL-safe slug. Forwards
// to orgsSvc.BySlug.
func (a *TheAuth) OrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return a.orgsSvc.BySlug(ctx, slug)
}

// OrganizationByID looks up an organization by ULID. Forwards to
// orgsSvc.ByID.
func (a *TheAuth) OrganizationByID(ctx context.Context, id ULID) (*Organization, error) {
	return a.orgsSvc.ByID(ctx, id)
}

// AddOrganizationMember adds (or updates the role of) a user inside an
// organization. Roles must be one of "owner", "admin", "member".
//
// security audit M2 (2026-06-20): when the upsert would demote the last
// remaining owner (role != owner on a user who is currently the sole
// owner), the call is rejected with ErrLastOwner. Forwards to
// orgsSvc.AddMember.
func (a *TheAuth) AddOrganizationMember(ctx context.Context, orgID, userID ULID, role string) error {
	return a.orgsSvc.AddMember(ctx, orgID, userID, role)
}

// RemoveOrganizationMember removes a user from an organization. Refuses
// to remove the last remaining owner (returns ErrLastOwner). Forwards to
// orgsSvc.RemoveMember.
func (a *TheAuth) RemoveOrganizationMember(ctx context.Context, orgID, userID ULID) error {
	return a.orgsSvc.RemoveMember(ctx, orgID, userID)
}

// ListOrganizationMembers returns every member of the supplied
// organization. Forwards to orgsSvc.ListMembers.
func (a *TheAuth) ListOrganizationMembers(ctx context.Context, orgID ULID) ([]OrganizationMember, error) {
	return a.orgsSvc.ListMembers(ctx, orgID)
}

// ListUserOrganizations returns every organization the user is a member
// of. Forwards to orgsSvc.ListUserOrganizations.
func (a *TheAuth) ListUserOrganizations(ctx context.Context, userID ULID) ([]Organization, error) {
	return a.orgsSvc.ListUserOrganizations(ctx, userID)
}

// SetActiveOrganization sets (or clears, when orgID is nil) the active
// organization on a session. The caller is responsible for verifying
// that the session's user is a member of orgID before calling. Forwards
// to orgsSvc.SetActive.
func (a *TheAuth) SetActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error {
	return a.orgsSvc.SetActive(ctx, sessionID, orgID)
}

// ---------- RBAC ----------

// SeedPermissions ensures every seeded + consumer-extended permission
// row exists in storage. Idempotent on the permissions.name unique
// index. Returns the canonical permission rows (with their persisted
// IDs) so the caller can reuse them for role assignments.
//
// SeedPermissions runs lazily on first SeedOrganizationRoles /
// CreateRole invocation; consumers wanting eager seeding at app start
// may call it directly from their bootstrap. Forwards to
// rbacSvc.SeedPermissions.
func (a *TheAuth) SeedPermissions(ctx context.Context) ([]Permission, error) {
	return a.rbacSvc.SeedPermissions(ctx)
}

// SeedOrganizationRoles creates the three default roles (or whatever
// the consumer configured) for one organization. Idempotent on
// (organization_id, name); existing roles keep their IDs and have their
// permission set reconciled against the seed. Forwards to
// rbacSvc.SeedOrgRoles.
func (a *TheAuth) SeedOrganizationRoles(ctx context.Context, orgID ULID) error {
	return a.rbacSvc.SeedOrgRoles(ctx, orgID)
}

// PermissionsForUser returns the user's permission set scoped to orgID
// (nil orgID returns only system-role permissions, i.e. super_admin).
// Sorted alphabetically for deterministic output. Forwards to
// rbacSvc.PermissionsForUser.
func (a *TheAuth) PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error) {
	return a.rbacSvc.PermissionsForUser(ctx, userID, orgID)
}

// HasPermission returns true when the user holds the named permission
// in the given organization, OR when the user holds the system
// super_admin role (which bypasses every check). orgID may be nil to
// ask only about system permissions. Forwards to rbacSvc.HasPermission.
func (a *TheAuth) HasPermission(ctx context.Context, userID ULID, orgID *ULID, perm string) (bool, error) {
	return a.rbacSvc.HasPermission(ctx, userID, orgID, perm)
}

// GrantRole assigns roleID to the target user. The actor must already
// have permission to grant; callers should run the RequirePermission
// middleware upstream of this method. Idempotent on (user_id, role_id).
// Emits action "role.granted" with role_id and role_name in metadata.
// Forwards to rbacSvc.GrantRole.
func (a *TheAuth) GrantRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.GrantRole(ctx, actor, target, roleID)
}

// RevokeRole removes roleID from the target user. Emits "role.revoked".
// Forwards to rbacSvc.RevokeRole.
func (a *TheAuth) RevokeRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.RevokeRole(ctx, actor, target, roleID)
}

// CreateRole adds a new role to orgID with the listed permissions.
// Names are unique per org; returns the storage error (typically a
// unique-violation translation) on collision. Emits "role.created".
// Forwards to rbacSvc.CreateRole.
func (a *TheAuth) CreateRole(ctx context.Context, orgID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.CreateRole(ctx, orgID, name, description, perms)
}

// UpdateRole rewrites name / description / permissions on an existing
// role. nil-valued fields are not touched (caller passes the current
// value). Emits "role.updated". Forwards to rbacSvc.UpdateRole.
func (a *TheAuth) UpdateRole(ctx context.Context, roleID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.UpdateRole(ctx, roleID, name, description, perms)
}

// DeleteRole removes a role. Returns ErrRoleInUse when the role is the
// sole grantor of users:admin in its organization (lockout protection).
// Emits "role.deleted". Forwards to rbacSvc.DeleteRole.
func (a *TheAuth) DeleteRole(ctx context.Context, roleID ULID) error {
	return a.rbacSvc.DeleteRole(ctx, roleID)
}

// ---------- Delegation ----------

// GrantDelegation persists a delegation_grants row. Scope MUST be a
// subset of the configured ProtectedResource scopes; resource MUST
// match a known ProtectedResource identifier; max_duration_seconds MUST
// be > 0 and <= AgentConfig.MaxDelegationDuration. Forwards to
// delegationSvc.GrantDelegation.
func (a *TheAuth) GrantDelegation(ctx context.Context, in GrantDelegationInput) (DelegationGrant, error) {
	return a.delegationSvc.GrantDelegation(ctx, in)
}

// ListDelegationsForUser returns every grant the user has issued,
// including revoked ones (for audit / display). Forwards to
// delegationSvc.ListDelegationsForUser.
func (a *TheAuth) ListDelegationsForUser(ctx context.Context, userID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForUser(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the supplied
// agent. Forwards to delegationSvc.ListDelegationsForAgent.
func (a *TheAuth) ListDelegationsForAgent(ctx context.Context, agentID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForAgent(ctx, agentID)
}

// RevokeDelegation marks a grant revoked. Cascade: every token already
// minted under this grant becomes invalid on the next resource server
// introspection refresh (worst case IntrospectionCacheTTL, default 60s).
// Forwards to delegationSvc.RevokeDelegation.
func (a *TheAuth) RevokeDelegation(ctx context.Context, grantID ULID, reason string) error {
	return a.delegationSvc.RevokeDelegation(ctx, grantID, reason)
}

package theauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/organizations"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	internalscim "github.com/glincker/theauth-go/v2/internal/scim"
)

// CreateSCIMToken mints a 256-bit token and returns the plaintext once. Only its sha256 hash is stored.
func (a *TheAuth) CreateSCIMToken(ctx context.Context, orgID ULID, name string) (string, SCIMToken, error) {
	token, rec, err := a.scimSvc.CreateToken(ctx, orgID, name)
	if errors.Is(err, internalscim.ErrSCIMDisabled) {
		return "", SCIMToken{}, errors.New("theauth: SCIM not enabled")
	}
	return token, rec, err
}

// RevokeSCIMToken marks the token revoked. Revoked tokens still resolve by hash, but the middleware
// refuses them.
func (a *TheAuth) RevokeSCIMToken(ctx context.Context, id ULID) error {
	return a.scimSvc.RevokeToken(ctx, id)
}

// ListSCIMTokens returns every token for the org, revoked or not.
func (a *TheAuth) ListSCIMTokens(ctx context.Context, orgID ULID) ([]SCIMToken, error) {
	return a.scimSvc.ListTokens(ctx, orgID)
}

// SCIMAuthResult is returned by AuthenticateSCIMToken. Bundling OrgID and TokenID avoids a second
// storage lookup.
type SCIMAuthResult struct {
	OrgID   ULID
	TokenID ULID
}

// AuthenticateSCIMToken is the entry point of the SCIM bearer middleware, run on every request. It
// resolves the org and token in one storage round trip and touches last_used_at asynchronously.
func (a *TheAuth) AuthenticateSCIMToken(ctx context.Context, presented string) (SCIMAuthResult, error) {
	res, err := a.scimSvc.Authenticate(ctx, presented)
	if err != nil {
		return SCIMAuthResult{}, err
	}
	return SCIMAuthResult{OrgID: res.OrganizationID, TokenID: res.TokenID}, nil
}

// CreateOrganization writes a new org and makes the user its owner. The slug is lowercased and
// validated; storage enforces uniqueness.
func (a *TheAuth) CreateOrganization(ctx context.Context, name, slug string, ownerUserID ULID) (Organization, error) {
	org, err := a.orgsSvc.Create(ctx, name, slug, ownerUserID)
	if errors.Is(err, organizations.ErrOrganizationsDisabled) {
		return Organization{}, errors.New("theauth: organizations not enabled")
	}
	return org, err
}

// OrganizationBySlug looks up an organization by URL-safe slug.
func (a *TheAuth) OrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return a.orgsSvc.BySlug(ctx, slug)
}

// OrganizationByID looks up an organization by ULID.
func (a *TheAuth) OrganizationByID(ctx context.Context, id ULID) (*Organization, error) {
	return a.orgsSvc.ByID(ctx, id)
}

// AddOrganizationMember adds a user to an organization or updates their role ("owner", "admin" or
// "member"). It refuses to demote the last owner (ErrLastOwner).
func (a *TheAuth) AddOrganizationMember(ctx context.Context, orgID, userID ULID, role string) error {
	return a.orgsSvc.AddMember(ctx, orgID, userID, role)
}

// RemoveOrganizationMember removes a user. It refuses to remove the last owner (ErrLastOwner).
func (a *TheAuth) RemoveOrganizationMember(ctx context.Context, orgID, userID ULID) error {
	return a.orgsSvc.RemoveMember(ctx, orgID, userID)
}

// ListOrganizationMembers returns every member of the organization.
func (a *TheAuth) ListOrganizationMembers(ctx context.Context, orgID ULID) ([]OrganizationMember, error) {
	return a.orgsSvc.ListMembers(ctx, orgID)
}

// ListUserOrganizations returns every organization the user belongs to.
func (a *TheAuth) ListUserOrganizations(ctx context.Context, userID ULID) ([]Organization, error) {
	return a.orgsSvc.ListUserOrganizations(ctx, userID)
}

// SetActiveOrganization sets (or with a nil orgID clears) the session's active organization. The
// caller must verify membership first. OnOrgSwitch fires on success in both directions, with an
// empty string when clearing.
func (a *TheAuth) SetActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error {
	if err := a.orgsSvc.SetActive(ctx, sessionID, orgID); err != nil {
		return err
	}
	if sess, serr := a.storage.SessionByID(ctx, sessionID); serr == nil && sess != nil {
		if user, uerr := a.storage.UserByID(ctx, sess.UserID); uerr == nil {
			orgIDStr := ""
			if orgID != nil {
				orgIDStr = orgID.String()
			}
			a.fireOnOrgSwitch(ctx, user, orgIDStr)
		}
	}
	return nil
}

// autoProvisionPersonalOrg creates a personal organization for a freshly created user and makes it
// active. It is a silent no-op unless Tenancy.AutoCreatePersonalOrg and Organizations are enabled.
// Errors are logged, never returned, since the user already exists.
func (a *TheAuth) autoProvisionPersonalOrg(ctx context.Context, user *User, sessionToken string) {
	if a.tenancyCfg == nil || !a.tenancyCfg.AutoCreatePersonalOrg || a.orgsSvc == nil || user == nil {
		return
	}
	name := user.Email
	if a.tenancyCfg.PersonalOrgNameFn != nil {
		name = a.tenancyCfg.PersonalOrgNameFn(user)
	}
	if name == "" {
		name = "Personal"
	}
	slug := "personal-" + strings.ToLower(user.ID.String())
	if a.tenancyCfg.PersonalOrgSlugFn != nil {
		slug = a.tenancyCfg.PersonalOrgSlugFn(user)
	}
	org, err := a.orgsSvc.Create(ctx, name, slug, user.ID)
	if err != nil {
		slog.WarnContext(ctx, "theauth: auto-create personal org failed", "user_id", user.ID.String(), "err", err.Error())
		return
	}
	if sessionToken == "" {
		return
	}
	sess := a.sessionFromToken(ctx, sessionToken)
	if sess == nil {
		return
	}
	orgID := org.ID
	if err := a.orgsSvc.SetActive(ctx, sess.ID, &orgID); err != nil {
		slog.WarnContext(ctx, "theauth: set active personal org failed", "user_id", user.ID.String(), "org_id", org.ID.String(), "err", err.Error())
	}
}

// SeedPermissions ensures every seeded and consumer-extended permission row exists. It is
// idempotent and runs lazily on the first role seeding, so apps may call it eagerly at startup.
func (a *TheAuth) SeedPermissions(ctx context.Context) ([]Permission, error) {
	return a.rbacSvc.SeedPermissions(ctx)
}

// SeedOrganizationRoles creates the default roles for one organization. It is idempotent on
// (organization_id, name) and reconciles existing roles' permissions against the seed.
func (a *TheAuth) SeedOrganizationRoles(ctx context.Context, orgID ULID) error {
	return a.rbacSvc.SeedOrgRoles(ctx, orgID)
}

// PermissionsForUser returns the user's permissions in orgID, sorted. A nil orgID returns
// system-role permissions only.
func (a *TheAuth) PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error) {
	return a.rbacSvc.PermissionsForUser(ctx, userID, orgID)
}

// HasPermission reports whether the user holds perm in orgID, or is a super_admin (which bypasses
// every check).
func (a *TheAuth) HasPermission(ctx context.Context, userID ULID, orgID *ULID, perm string) (bool, error) {
	return a.rbacSvc.HasPermission(ctx, userID, orgID, perm)
}

// GrantRole assigns roleID to target. The actor must already be allowed to grant; run
// RequirePermission upstream. It is idempotent and emits role.granted.
func (a *TheAuth) GrantRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.GrantRole(ctx, actor, target, roleID)
}

// RevokeRole removes roleID from target and emits role.revoked.
func (a *TheAuth) RevokeRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.RevokeRole(ctx, actor, target, roleID)
}

// CreateRole adds a role with the listed permissions. Names are unique per organization and emit
// role.created.
func (a *TheAuth) CreateRole(ctx context.Context, orgID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.CreateRole(ctx, orgID, name, description, perms)
}

// UpdateRole rewrites a role's name, description and permissions. Emits role.updated.
func (a *TheAuth) UpdateRole(ctx context.Context, roleID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.UpdateRole(ctx, roleID, name, description, perms)
}

// DeleteRole removes a role. It returns ErrRoleInUse when the role is the sole grantor of
// users:admin in its organization.
func (a *TheAuth) DeleteRole(ctx context.Context, roleID ULID) error {
	return a.rbacSvc.DeleteRole(ctx, roleID)
}

// GrantDelegation persists a delegation grant. Scope must be a subset of the resource's scopes,
// resource must be a known ProtectedResource, and max_duration_seconds must be within
// AgentConfig.MaxDelegationDuration.
func (a *TheAuth) GrantDelegation(ctx context.Context, in GrantDelegationInput) (DelegationGrant, error) {
	return a.delegationSvc.GrantDelegation(ctx, in)
}

// ListDelegationsForUser returns every grant the user issued, including revoked ones.
func (a *TheAuth) ListDelegationsForUser(ctx context.Context, userID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForUser(ctx, userID)
}

// ListDelegationsForAgent returns every grant naming the agent.
func (a *TheAuth) ListDelegationsForAgent(ctx context.Context, agentID ULID) ([]DelegationGrant, error) {
	return a.delegationSvc.ListDelegationsForAgent(ctx, agentID)
}

// RevokeDelegation marks a grant revoked. Tokens minted under it become invalid at the next
// introspection refresh (worst case IntrospectionCacheTTL).
func (a *TheAuth) RevokeDelegation(ctx context.Context, grantID ULID, reason string) error {
	return a.delegationSvc.RevokeDelegation(ctx, grantID, reason)
}

// The seeded permission catalog. Consumers extend it and never shrink it. New fails if a custom
// permission duplicates a seeded name with a different description. The list is intentionally
// finite; wildcards and ABAC are not supported.
const (
	PermissionBillingRead    = models.PermissionBillingRead
	PermissionBillingWrite   = models.PermissionBillingWrite
	PermissionBillingAdmin   = models.PermissionBillingAdmin
	PermissionUsersRead      = models.PermissionUsersRead
	PermissionUsersInvite    = models.PermissionUsersInvite
	PermissionUsersAdmin     = models.PermissionUsersAdmin
	PermissionRolesRead      = models.PermissionRolesRead
	PermissionRolesAdmin     = models.PermissionRolesAdmin
	PermissionAuditRead      = models.PermissionAuditRead
	PermissionSAMLAdmin      = models.PermissionSAMLAdmin
	PermissionSCIMAdmin      = models.PermissionSCIMAdmin
	PermissionSessionsRevoke = models.PermissionSessionsRevoke

	// agents:admin and delegations:admin grant agent and delegation CRUD under /admin/v1 (seeded into
	// owner and admin roles).
	PermissionAgentsAdmin      = models.PermissionAgentsAdmin
	PermissionDelegationsAdmin = models.PermissionDelegationsAdmin

	// PermissionAccountLink and its siblings are user-scoped; admin overrides go through /admin/v1.
	PermissionAccountLink  = models.PermissionAccountLink
	PermissionAccountMerge = models.PermissionAccountMerge
)

// SeededPermissions returns the canonical permission catalog by value, so callers cannot mutate
// library state.
func SeededPermissions() []Permission { return rbac.SeededPermissions() }

// DefaultRoleSeeds returns the three default organization roles seeded into every new organization.
// The reserved names "owner", "admin" and "member" must stay present when Config.RBAC.DefaultRoles
// overrides them.
func DefaultRoleSeeds() []RoleSeed { return rbac.DefaultRoleSeeds() }

func validateRBAC(cfg *RBACConfig) ([]Permission, map[string]Permission, []RoleSeed, error) {
	if cfg == nil {
		return rbac.Validate(nil, nil)
	}
	return rbac.Validate(cfg.Permissions, cfg.DefaultRoles)
}

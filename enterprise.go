package theauth

// enterprise.go consolidates the v0.7 to v1.0 enterprise surface
// (SCIM tokens, organizations + membership, RBAC permission catalog
// and forwarders, agent delegations) into a single file. PR I
// (2026-06-22) merged the prior forwarders_enterprise.go and rbac.go
// files here so the repository root has fewer files and the README
// renders above the fold on GitHub. The RBAC permission catalog,
// validation, and per-request cache live in the second half; every
// forwarder method is a thin thunk over the matching internal/<flow>
// Service. Public API surface and signatures are byte-stable.

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/organizations"
	internalscim "github.com/glincker/theauth-go/internal/scim"
)

// ---------- Enterprise forwarders (SCIM tokens, orgs, RBAC, delegations) ----------

// PR G (2026-06-21) merged the previous
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
// to orgsSvc.SetActive, then fires OnOrgSwitch on success. orgID being
// nil (clearing the active org) still fires the hook with an empty
// string so consumers can observe both directions.
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

// autoProvisionPersonalOrg is the v2.5 tenancy auto-provisioner. Called by
// the signup forwarders when the user row is freshly created. Creates a
// personal organization, adds the user as owner (CreateOrganization
// already does that internally), and sets it as the session's active org.
// Silent no-op when Tenancy is nil, Tenancy.AutoCreatePersonalOrg is
// false, Organizations is not enabled, or any required service is nil.
// Errors are logged but do NOT fail the surrounding signup; the user has
// already been created and a missing personal org is recoverable.
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

// ---------- RBAC permission catalog, validation, and per-request cache ----------

// Seeded permission catalog. Every consumer's permission set extends (never
// shrinks) this list; New returns an error if a custom Permission name
// duplicates a seeded one with a different description (defensive against
// silent overrides).
//
// The catalog values live in internal/models so storage adapters can
// reference the same string literals without importing the root package.
// The list is intentionally finite and small. Wildcards and ABAC are
// deferred to v1.x per the v1.0 design document.
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

	// v2.0 phase 6 additions. agents:admin grants organization-scoped
	// agent CRUD via /admin/v1/.../agents; delegations:admin grants
	// delegation CRUD via /admin/v1/.../delegations. Seeded into every
	// organization's "owner" and "admin" default roles.
	PermissionAgentsAdmin      = models.PermissionAgentsAdmin
	PermissionDelegationsAdmin = models.PermissionDelegationsAdmin

	// v2.3 identity-linking permissions. Both are user-scoped (caller can
	// only link/merge their own account); admin override paths go through
	// the /admin/v1 surface.
	PermissionAccountLink  = models.PermissionAccountLink
	PermissionAccountMerge = models.PermissionAccountMerge
)

// SeededPermissions returns the v1.0 canonical permission catalog. The
// slice is returned by value (callers may not mutate the library state).
func SeededPermissions() []Permission {
	return []Permission{
		{Name: PermissionBillingRead, Description: "View invoices, plans, payment methods."},
		{Name: PermissionBillingWrite, Description: "Update plan, change payment method, initiate refund."},
		{Name: PermissionBillingAdmin, Description: "Cancel subscription, transfer billing ownership."},
		{Name: PermissionUsersRead, Description: "List members of the active organization."},
		{Name: PermissionUsersInvite, Description: "Send organization invites."},
		{Name: PermissionUsersAdmin, Description: "Update member status, remove from org, change member role."},
		{Name: PermissionRolesRead, Description: "List custom roles and their permissions."},
		{Name: PermissionRolesAdmin, Description: "Create, update, delete custom roles."},
		{Name: PermissionAuditRead, Description: "Query the organization's audit log."},
		{Name: PermissionSAMLAdmin, Description: "Create, update, delete SAML connections."},
		{Name: PermissionSCIMAdmin, Description: "Manage SCIM bearer tokens and provisioning."},
		{Name: PermissionSessionsRevoke, Description: "Revoke another member's active sessions."},
		{Name: PermissionAgentsAdmin, Description: "Create, update, suspend, revoke organization-owned agents."},
		{Name: PermissionDelegationsAdmin, Description: "Create and revoke delegation grants on behalf of users in the organization."},
	}
}

// DefaultRoleSeeds returns the three default organization roles seeded into
// every new organization. Consumers may extend with additional roles via
// Config.RBAC.DefaultRoles; the three reserved names ("owner", "admin",
// "member") must always remain present.
func DefaultRoleSeeds() []RoleSeed {
	all := SeededPermissions()
	allNames := make([]string, 0, len(all))
	for _, p := range all {
		allNames = append(allNames, p.Name)
	}
	adminPerms := make([]string, 0, len(all)-1)
	for _, n := range allNames {
		if n == PermissionBillingAdmin {
			continue
		}
		adminPerms = append(adminPerms, n)
	}
	return []RoleSeed{
		{Name: OrgRoleOwner, Description: "Full administrative control.", Permissions: allNames},
		{Name: OrgRoleAdmin, Description: "Day-to-day administration without billing cancellation.", Permissions: adminPerms},
		{Name: OrgRoleMember, Description: "Read-only member of the organization.", Permissions: []string{PermissionUsersRead, PermissionAuditRead}},
	}
}

// permissionCache is a per-request cache for RequirePermission. One DB read
// hydrates the user's permission set; subsequent middleware in the same
// request reuse the cached map.
type permissionCache struct {
	once sync.Once
	set  map[string]struct{}
	err  error
	// orgID identifies which org scope this cache holds. If the same
	// request asks about a different org, the cache is invalidated.
	orgID *ULID
	// superAdmin records whether the user holds the system super_admin role.
	superAdmin bool
}

// validPermissionName returns true if s is a valid permission identifier:
// non-empty, ASCII printable, no whitespace, no control characters. Allowed
// punctuation is ":", "_", "-", ".". Used at New time on Config.Permissions
// to surface typos at startup instead of on the first permission check.
func validPermissionName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > 0x7e || r < 0x21 {
			return false
		}
		// 0x21 to 0x7e is printable ASCII. Already excludes whitespace and
		// control characters. No further checks needed; we deliberately
		// allow ":" "_" "-" "." which are all in that range.
	}
	return true
}

// validateRBAC normalises the configured RBAC block and produces the
// permission catalog, name index, and default role seeds the runtime uses.
// Returns ErrUnknownPermission (wrapped) when a default-role permission
// references an unknown permission name.
func validateRBAC(cfg *RBACConfig) (catalog []Permission, index map[string]Permission, seeds []RoleSeed, err error) {
	catalog = append(catalog, SeededPermissions()...)
	index = make(map[string]Permission, len(catalog))
	for _, p := range catalog {
		index[p.Name] = p
	}
	if cfg != nil {
		for _, p := range cfg.Permissions {
			if !validPermissionName(p.Name) {
				return nil, nil, nil, &TheAuthError{Code: "rbac.invalid_permission_name", Message: p.Name}
			}
			if existing, dup := index[p.Name]; dup {
				// Duplicate names are tolerated when descriptions match;
				// otherwise reject so silent overrides cannot happen.
				if existing.Description != "" && p.Description != "" && existing.Description != p.Description {
					return nil, nil, nil, &TheAuthError{Code: "rbac.duplicate_permission", Message: p.Name}
				}
				continue
			}
			index[p.Name] = p
			catalog = append(catalog, p)
		}
	}
	// Default role seeds.
	if cfg == nil || len(cfg.DefaultRoles) == 0 {
		seeds = DefaultRoleSeeds()
	} else {
		seeds = cfg.DefaultRoles
		// Reserved names must remain present.
		have := map[string]bool{}
		for _, s := range seeds {
			have[s.Name] = true
		}
		for _, n := range []string{OrgRoleOwner, OrgRoleAdmin, OrgRoleMember} {
			if !have[n] {
				return nil, nil, nil, &TheAuthError{Code: "rbac.missing_reserved_role", Message: n}
			}
		}
	}
	// Every permission referenced by a default role must exist in the
	// catalog.
	for _, s := range seeds {
		for _, perm := range s.Permissions {
			if _, ok := index[perm]; !ok {
				return nil, nil, nil, &TheAuthError{Code: "rbac.unknown_permission", Message: s.Name + ": " + perm, Inner: ErrUnknownPermission}
			}
		}
	}
	// Deterministic catalog order for tests + read APIs.
	sort.Slice(catalog, func(i, j int) bool { return catalog[i].Name < catalog[j].Name })
	return catalog, index, seeds, nil
}

// permissionSetFromList materialises a string set for fast membership
// queries.
func permissionSetFromList(list []string) map[string]struct{} {
	out := make(map[string]struct{}, len(list))
	for _, p := range list {
		out[p] = struct{}{}
	}
	return out
}

// ctxKeyPermCache is the request context key for the permission cache.
// Distinct from the auth context keys so RequireAuth and RequirePermission
// can be reordered without aliasing.
type ctxKeyPermCacheT struct{}

var ctxKeyPermCache ctxKeyPermCacheT

func withPermissionCache(ctx context.Context, c *permissionCache) context.Context {
	return context.WithValue(ctx, ctxKeyPermCache, c)
}

func permissionCacheFromContext(ctx context.Context) (*permissionCache, bool) {
	c, ok := ctx.Value(ctxKeyPermCache).(*permissionCache)
	return c, ok
}

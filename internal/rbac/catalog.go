package rbac

import (
	"context"
	"sort"
	"sync"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// SeededPermissions returns the v1.0 canonical permission catalog. The
// slice is returned by value (callers may not mutate the library state).
func SeededPermissions() []models.Permission {
	return []models.Permission{
		{Name: models.PermissionBillingRead, Description: "View invoices, plans, payment methods."},
		{Name: models.PermissionBillingWrite, Description: "Update plan, change payment method, initiate refund."},
		{Name: models.PermissionBillingAdmin, Description: "Cancel subscription, transfer billing ownership."},
		{Name: models.PermissionUsersRead, Description: "List members of the active organization."},
		{Name: models.PermissionUsersInvite, Description: "Send organization invites."},
		{Name: models.PermissionUsersAdmin, Description: "Update member status, remove from org, change member role."},
		{Name: models.PermissionRolesRead, Description: "List custom roles and their permissions."},
		{Name: models.PermissionRolesAdmin, Description: "Create, update, delete custom roles."},
		{Name: models.PermissionAuditRead, Description: "Query the organization's audit log."},
		{Name: models.PermissionSAMLAdmin, Description: "Create, update, delete SAML connections."},
		{Name: models.PermissionSCIMAdmin, Description: "Manage SCIM bearer tokens and provisioning."},
		{Name: models.PermissionSessionsRevoke, Description: "Revoke another member's active sessions."},
		{Name: models.PermissionAgentsAdmin, Description: "Create, update, suspend, revoke organization-owned agents."},
		{Name: models.PermissionDelegationsAdmin, Description: "Create and revoke delegation grants on behalf of users in the organization."},
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
		if n == models.PermissionBillingAdmin {
			continue
		}
		adminPerms = append(adminPerms, n)
	}
	return []RoleSeed{
		{Name: models.OrgRoleOwner, Description: "Full administrative control.", Permissions: allNames},
		{Name: models.OrgRoleAdmin, Description: "Day-to-day administration without billing cancellation.", Permissions: adminPerms},
		{Name: models.OrgRoleMember, Description: "Read-only member of the organization.", Permissions: []string{models.PermissionUsersRead, models.PermissionAuditRead}},
	}
}

// PermissionCache is a per-request cache for RequirePermission. One DB read
// hydrates the user's permission set; subsequent middleware in the same
// request reuse the cached map.
type PermissionCache struct {
	Once sync.Once
	Set  map[string]struct{}
	Err  error
	// orgID identifies which org scope this cache holds. If the same
	// request asks about a different org, the cache is invalidated.
	OrgID *models.ULID
	// superAdmin records whether the user holds the system super_admin role.
	SuperAdmin bool
}

// ValidPermissionName returns true if s is a valid permission identifier:
// non-empty, ASCII printable, no whitespace, no control characters. Allowed
// punctuation is ":", "_", "-", ".". Used at New time on Config.Permissions
// to surface typos at startup instead of on the first permission check.
func ValidPermissionName(s string) bool {
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

// Validate normalises the configured RBAC block and produces the
// permission catalog, name index, and default role seeds the runtime uses.
// Returns models.ErrUnknownPermission (wrapped) when a default-role permission
// references an unknown permission name.
func Validate(extra []models.Permission, roles []RoleSeed) (catalog []models.Permission, index map[string]models.Permission, seeds []RoleSeed, err error) {
	catalog = append(catalog, SeededPermissions()...)
	index = make(map[string]models.Permission, len(catalog))
	for _, p := range catalog {
		index[p.Name] = p
	}
	{
		for _, p := range extra {
			if !ValidPermissionName(p.Name) {
				return nil, nil, nil, &models.TheAuthError{Code: "rbac.invalid_permission_name", Message: p.Name}
			}
			if existing, dup := index[p.Name]; dup {
				// Duplicate names are tolerated when descriptions match;
				// otherwise reject so silent overrides cannot happen.
				if existing.Description != "" && p.Description != "" && existing.Description != p.Description {
					return nil, nil, nil, &models.TheAuthError{Code: "rbac.duplicate_permission", Message: p.Name}
				}
				continue
			}
			index[p.Name] = p
			catalog = append(catalog, p)
		}
	}
	// Default role seeds.
	if len(roles) == 0 {
		seeds = DefaultRoleSeeds()
	} else {
		seeds = roles
		// Reserved names must remain present.
		have := map[string]bool{}
		for _, s := range seeds {
			have[s.Name] = true
		}
		for _, n := range []string{models.OrgRoleOwner, models.OrgRoleAdmin, models.OrgRoleMember} {
			if !have[n] {
				return nil, nil, nil, &models.TheAuthError{Code: "rbac.missing_reserved_role", Message: n}
			}
		}
	}
	// Every permission referenced by a default role must exist in the
	// catalog.
	for _, s := range seeds {
		for _, perm := range s.Permissions {
			if _, ok := index[perm]; !ok {
				return nil, nil, nil, &models.TheAuthError{Code: "rbac.unknown_permission", Message: s.Name + ": " + perm, Inner: models.ErrUnknownPermission}
			}
		}
	}
	// Deterministic catalog order for tests + read APIs.
	sort.Slice(catalog, func(i, j int) bool { return catalog[i].Name < catalog[j].Name })
	return catalog, index, seeds, nil
}

// SetFromList materialises a string set for fast membership
// queries.
func SetFromList(list []string) map[string]struct{} {
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

func WithPermissionCache(ctx context.Context, c *PermissionCache) context.Context {
	return context.WithValue(ctx, ctxKeyPermCache, c)
}

func PermissionCacheFromContext(ctx context.Context) (*PermissionCache, bool) {
	c, ok := ctx.Value(ctxKeyPermCache).(*PermissionCache)
	return c, ok
}

package theauth

import (
	"context"
	"sort"
	"sync"
)

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

package theauth

import (
	"context"
	"errors"
	"strings"

	"github.com/glincker/theauth-go/internal/ulid"
)

// CreateOrganization writes a new org row and adds the supplied user as its
// owner. Slug is lowercased and validated against the slug rules in
// validateSlug; the storage layer enforces uniqueness.
func (a *TheAuth) CreateOrganization(ctx context.Context, name, slug string, ownerUserID ULID) (Organization, error) {
	if a.orgsCfg == nil {
		return Organization{}, errors.New("theauth: organizations not enabled")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Organization{}, errors.New("theauth: organization name is required")
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateSlug(slug); err != nil {
		return Organization{}, err
	}
	o := Organization{
		ID:   ulid.New(),
		Name: name,
		Slug: slug,
	}
	created, err := a.storage.InsertOrganization(ctx, o)
	if err != nil {
		return Organization{}, err
	}
	if err := a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: created.ID,
		UserID:         ownerUserID,
		Role:           OrgRoleOwner,
	}); err != nil {
		return Organization{}, err
	}
	return created, nil
}

// OrganizationBySlug looks up an organization by URL-safe slug.
func (a *TheAuth) OrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return a.storage.OrganizationBySlug(ctx, strings.ToLower(slug))
}

// OrganizationByID looks up an organization by ULID.
func (a *TheAuth) OrganizationByID(ctx context.Context, id ULID) (*Organization, error) {
	return a.storage.OrganizationByID(ctx, id)
}

// AddOrganizationMember adds (or updates the role of) a user inside an
// organization. Roles must be one of "owner", "admin", "member".
//
// security audit M2 (2026-06-20): when the upsert would demote the last
// remaining owner (role != owner on a user who is currently the sole
// owner), the call is rejected with ErrLastOwner. Without this guard, an
// admin could orphan the organization by setting the last owner's role
// to "member" via the upsert path (RemoveOrganizationMember already
// enforces the same invariant on deletes).
func (a *TheAuth) AddOrganizationMember(ctx context.Context, orgID, userID ULID, role string) error {
	if !isValidRole(role) {
		return errors.New("theauth: invalid organization role")
	}
	if role != OrgRoleOwner {
		// Only the demote path needs the guard: promoting to owner is
		// always safe (the org gains an owner), and adding a fresh
		// member/admin row never affects existing owner state.
		current, err := a.storage.OrganizationMemberRole(ctx, orgID, userID)
		if err == nil && current == OrgRoleOwner {
			members, err := a.storage.OrganizationMembersByOrg(ctx, orgID)
			if err != nil {
				return err
			}
			owners := 0
			for _, m := range members {
				if m.Role == OrgRoleOwner {
					owners++
				}
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}
	}
	return a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           role,
	})
}

// RemoveOrganizationMember removes a user from an organization. Refuses to
// remove the last remaining owner (returns ErrLastOwner).
func (a *TheAuth) RemoveOrganizationMember(ctx context.Context, orgID, userID ULID) error {
	role, err := a.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if role == OrgRoleOwner {
		members, err := a.storage.OrganizationMembersByOrg(ctx, orgID)
		if err != nil {
			return err
		}
		owners := 0
		for _, m := range members {
			if m.Role == OrgRoleOwner {
				owners++
			}
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	return a.storage.DeleteOrganizationMember(ctx, orgID, userID)
}

// ListOrganizationMembers returns every member of the supplied organization.
func (a *TheAuth) ListOrganizationMembers(ctx context.Context, orgID ULID) ([]OrganizationMember, error) {
	return a.storage.OrganizationMembersByOrg(ctx, orgID)
}

// ListUserOrganizations returns every organization the user is a member of.
func (a *TheAuth) ListUserOrganizations(ctx context.Context, userID ULID) ([]Organization, error) {
	return a.storage.OrganizationsByUser(ctx, userID)
}

// SetActiveOrganization sets (or clears, when orgID is nil) the active
// organization on a session. The caller is responsible for verifying that
// the session's user is a member of orgID before calling.
func (a *TheAuth) SetActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error {
	return a.storage.SetSessionActiveOrganization(ctx, sessionID, orgID)
}

// isValidRole reports whether the supplied role string is one of the three
// constants defined in models.go.
func isValidRole(r string) bool {
	switch r {
	case OrgRoleOwner, OrgRoleAdmin, OrgRoleMember:
		return true
	default:
		return false
	}
}

// validateSlug enforces the URL-safe handle subset: lowercase letters,
// digits, and hyphens; 1 to 64 characters; not starting or ending with a
// hyphen. We deliberately do not allow underscores or dots so the slug can
// always live in a path segment without escaping.
func validateSlug(slug string) error {
	if slug == "" {
		return errors.New("theauth: organization slug is required")
	}
	if len(slug) > 64 {
		return errors.New("theauth: organization slug is too long")
	}
	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return errors.New("theauth: organization slug cannot start or end with a hyphen")
	}
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return errors.New("theauth: organization slug may only contain lowercase letters, digits, and hyphens")
		}
	}
	return nil
}

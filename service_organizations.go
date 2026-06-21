package theauth

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/internal/organizations"
)

// Organization CRUD + membership forwarders. PR A architecture reorg
// (2026-06) moved the implementations to internal/organizations; the
// exported method signatures on *TheAuth are unchanged so handlers and
// consumer code keep compiling.

// CreateOrganization writes a new org row and adds the supplied user as
// its owner. Slug is lowercased and validated against the slug rules in
// the internal package; the storage layer enforces uniqueness.
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

// AddOrganizationMember adds (or updates the role of) a user inside an
// organization. Roles must be one of "owner", "admin", "member".
//
// security audit M2 (2026-06-20): when the upsert would demote the last
// remaining owner (role != owner on a user who is currently the sole
// owner), the call is rejected with ErrLastOwner.
func (a *TheAuth) AddOrganizationMember(ctx context.Context, orgID, userID ULID, role string) error {
	return a.orgsSvc.AddMember(ctx, orgID, userID, role)
}

// RemoveOrganizationMember removes a user from an organization. Refuses to
// remove the last remaining owner (returns ErrLastOwner).
func (a *TheAuth) RemoveOrganizationMember(ctx context.Context, orgID, userID ULID) error {
	return a.orgsSvc.RemoveMember(ctx, orgID, userID)
}

// ListOrganizationMembers returns every member of the supplied organization.
func (a *TheAuth) ListOrganizationMembers(ctx context.Context, orgID ULID) ([]OrganizationMember, error) {
	return a.orgsSvc.ListMembers(ctx, orgID)
}

// ListUserOrganizations returns every organization the user is a member of.
func (a *TheAuth) ListUserOrganizations(ctx context.Context, userID ULID) ([]Organization, error) {
	return a.orgsSvc.ListUserOrganizations(ctx, userID)
}

// SetActiveOrganization sets (or clears, when orgID is nil) the active
// organization on a session. The caller is responsible for verifying that
// the session's user is a member of orgID before calling.
func (a *TheAuth) SetActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error {
	return a.orgsSvc.SetActive(ctx, sessionID, orgID)
}

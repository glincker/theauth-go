// Package organizations owns the create / read / member-management surface
// for multi-tenant organizations. Extracted from root service_organizations.go
// in PR A of the 2026-06 architecture reorg.
//
// The package enforces two invariants the storage layer cannot: slug
// validation (URL-safe lowercase alphanumeric + hyphen) and the
// "cannot orphan the last owner" guard on both demote and remove paths.
package organizations

import (
	"context"
	"errors"
	"strings"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/organizations does not import
// the root theauth package and the constructor cycle stays broken.
type Storage interface {
	InsertOrganization(ctx context.Context, o models.Organization) (models.Organization, error)
	OrganizationByID(ctx context.Context, id models.ULID) (*models.Organization, error)
	OrganizationBySlug(ctx context.Context, slug string) (*models.Organization, error)
	UpsertOrganizationMember(ctx context.Context, m models.OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID models.ULID) error
	OrganizationMembersByOrg(ctx context.Context, orgID models.ULID) ([]models.OrganizationMember, error)
	OrganizationsByUser(ctx context.Context, userID models.ULID) ([]models.Organization, error)
	OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error)
	SetSessionActiveOrganization(ctx context.Context, sessionID models.ULID, orgID *models.ULID) error
}

// Config currently has no tunables; the presence of a non-nil pointer is
// the enabled signal. Mirrors the legacy theauth.OrganizationsConfig.
type Config struct{}

// ErrOrganizationsDisabled is returned by Service methods invoked when the
// root configuration did not enable organizations. The root forwarder
// translates this into the legacy "theauth: organizations not enabled"
// error string for backward compat.
var ErrOrganizationsDisabled = errors.New("organizations: not enabled")

// Service holds the dependencies needed for organization CRUD and
// membership management.
type Service struct {
	storage Storage
	cfg     *Config
}

// New constructs an organizations Service. cfg may be nil; in that case
// Create returns ErrOrganizationsDisabled.
func New(storage Storage, cfg *Config) *Service {
	return &Service{storage: storage, cfg: cfg}
}

// Create writes a new org row and adds the supplied user as its owner.
// Slug is lowercased and validated against the slug rules in validateSlug;
// the storage layer enforces uniqueness.
func (s *Service) Create(ctx context.Context, name, slug string, ownerUserID models.ULID) (models.Organization, error) {
	if s.cfg == nil {
		return models.Organization{}, ErrOrganizationsDisabled
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return models.Organization{}, errors.New("theauth: organization name is required")
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateSlug(slug); err != nil {
		return models.Organization{}, err
	}
	o := models.Organization{
		ID:   ulid.New(),
		Name: name,
		Slug: slug,
	}
	created, err := s.storage.InsertOrganization(ctx, o)
	if err != nil {
		return models.Organization{}, err
	}
	if err := s.storage.UpsertOrganizationMember(ctx, models.OrganizationMember{
		OrganizationID: created.ID,
		UserID:         ownerUserID,
		Role:           models.OrgRoleOwner,
	}); err != nil {
		return models.Organization{}, err
	}
	return created, nil
}

// BySlug looks up an organization by URL-safe slug.
func (s *Service) BySlug(ctx context.Context, slug string) (*models.Organization, error) {
	return s.storage.OrganizationBySlug(ctx, strings.ToLower(slug))
}

// ByID looks up an organization by ULID.
func (s *Service) ByID(ctx context.Context, id models.ULID) (*models.Organization, error) {
	return s.storage.OrganizationByID(ctx, id)
}

// AddMember adds (or updates the role of) a user inside an organization.
// Roles must be one of "owner", "admin", "member".
//
// security audit M2 (2026-06-20): when the upsert would demote the last
// remaining owner (role != owner on a user who is currently the sole
// owner), the call is rejected with models.ErrLastOwner. Without this
// guard, an admin could orphan the organization by setting the last
// owner's role to "member" via the upsert path (RemoveMember already
// enforces the same invariant on deletes).
func (s *Service) AddMember(ctx context.Context, orgID, userID models.ULID, role string) error {
	if !isValidRole(role) {
		return errors.New("theauth: invalid organization role")
	}
	if role != models.OrgRoleOwner {
		// Only the demote path needs the guard: promoting to owner is
		// always safe (the org gains an owner), and adding a fresh
		// member/admin row never affects existing owner state.
		current, err := s.storage.OrganizationMemberRole(ctx, orgID, userID)
		if err == nil && current == models.OrgRoleOwner {
			members, err := s.storage.OrganizationMembersByOrg(ctx, orgID)
			if err != nil {
				return err
			}
			owners := 0
			for _, m := range members {
				if m.Role == models.OrgRoleOwner {
					owners++
				}
			}
			if owners <= 1 {
				return models.ErrLastOwner
			}
		}
	}
	return s.storage.UpsertOrganizationMember(ctx, models.OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           role,
	})
}

// RemoveMember removes a user from an organization. Refuses to remove the
// last remaining owner (returns models.ErrLastOwner).
func (s *Service) RemoveMember(ctx context.Context, orgID, userID models.ULID) error {
	role, err := s.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if role == models.OrgRoleOwner {
		members, err := s.storage.OrganizationMembersByOrg(ctx, orgID)
		if err != nil {
			return err
		}
		owners := 0
		for _, m := range members {
			if m.Role == models.OrgRoleOwner {
				owners++
			}
		}
		if owners <= 1 {
			return models.ErrLastOwner
		}
	}
	return s.storage.DeleteOrganizationMember(ctx, orgID, userID)
}

// ListMembers returns every member of the supplied organization.
func (s *Service) ListMembers(ctx context.Context, orgID models.ULID) ([]models.OrganizationMember, error) {
	return s.storage.OrganizationMembersByOrg(ctx, orgID)
}

// ListUserOrganizations returns every organization the user is a member of.
func (s *Service) ListUserOrganizations(ctx context.Context, userID models.ULID) ([]models.Organization, error) {
	return s.storage.OrganizationsByUser(ctx, userID)
}

// SetActive sets (or clears, when orgID is nil) the active organization
// on a session. The caller is responsible for verifying that the
// session's user is a member of orgID before calling.
func (s *Service) SetActive(ctx context.Context, sessionID models.ULID, orgID *models.ULID) error {
	return s.storage.SetSessionActiveOrganization(ctx, sessionID, orgID)
}

// isValidRole reports whether the supplied role string is one of the three
// constants defined in internal/models.
func isValidRole(r string) bool {
	switch r {
	case models.OrgRoleOwner, models.OrgRoleAdmin, models.OrgRoleMember:
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

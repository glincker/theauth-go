package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	sqlcgen "github.com/glincker/theauth-go/storage/postgres/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// v0.7 storage extension: organizations, organization_members, sessions
// active_organization_id, saml_connections, saml_identities, scim_tokens,
// groups, group_members, plus a few helpers (UserByExternalIDInOrg,
// UpdateUserSCIM, ListUsersByOrganization, ListGroupsByOrganization).
// All methods are additive; v0.6 callers never invoke them.

// ---------- Organizations ----------

func rowToOrganization(r sqlcgen.Organization) theauth.Organization {
	return theauth.Organization{
		ID:        pgUUIDToULID(r.ID),
		Name:      r.Name,
		Slug:      r.Slug,
		CreatedAt: tsToTime(r.CreatedAt),
		UpdatedAt: tsToTime(r.UpdatedAt),
	}
}

func (s *Store) InsertOrganization(ctx context.Context, o theauth.Organization) (theauth.Organization, error) {
	row, err := s.q.InsertOrganization(ctx, sqlcgen.InsertOrganizationParams{
		ID:        ulidToPgUUID(o.ID),
		Name:      o.Name,
		Slug:      strings.ToLower(o.Slug),
		CreatedAt: timeToTs(o.CreatedAt),
		UpdatedAt: timeToTs(o.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err, "organizations_slug_key") {
			return theauth.Organization{}, theauth.ErrSlugTaken
		}
		return theauth.Organization{}, err
	}
	return rowToOrganization(row), nil
}

func (s *Store) OrganizationByID(ctx context.Context, id theauth.ULID) (*theauth.Organization, error) {
	row, err := s.q.OrganizationByID(ctx, ulidToPgUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	o := rowToOrganization(row)
	return &o, nil
}

func (s *Store) OrganizationBySlug(ctx context.Context, slug string) (*theauth.Organization, error) {
	row, err := s.q.OrganizationBySlug(ctx, strings.ToLower(slug))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	o := rowToOrganization(row)
	return &o, nil
}

func (s *Store) UpdateOrganization(ctx context.Context, o theauth.Organization) error {
	affected, err := s.q.UpdateOrganization(ctx, sqlcgen.UpdateOrganizationParams{
		ID:   ulidToPgUUID(o.ID),
		Name: o.Name,
		Slug: strings.ToLower(o.Slug),
	})
	if err != nil {
		if isUniqueViolation(err, "organizations_slug_key") {
			return theauth.ErrSlugTaken
		}
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id theauth.ULID) error {
	affected, err := s.q.DeleteOrganization(ctx, ulidToPgUUID(id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- Organization members ----------

func rowToOrgMember(r sqlcgen.OrganizationMember) theauth.OrganizationMember {
	return theauth.OrganizationMember{
		OrganizationID: pgUUIDToULID(r.OrganizationID),
		UserID:         pgUUIDToULID(r.UserID),
		Role:           r.Role,
		JoinedAt:       tsToTime(r.JoinedAt),
	}
}

func (s *Store) UpsertOrganizationMember(ctx context.Context, m theauth.OrganizationMember) error {
	joined := m.JoinedAt
	if joined.IsZero() {
		joined = time.Now()
	}
	return s.q.UpsertOrganizationMember(ctx, sqlcgen.UpsertOrganizationMemberParams{
		OrganizationID: ulidToPgUUID(m.OrganizationID),
		UserID:         ulidToPgUUID(m.UserID),
		Role:           m.Role,
		JoinedAt:       timeToTs(joined),
	})
}

func (s *Store) DeleteOrganizationMember(ctx context.Context, orgID, userID theauth.ULID) error {
	affected, err := s.q.DeleteOrganizationMember(ctx, sqlcgen.DeleteOrganizationMemberParams{
		OrganizationID: ulidToPgUUID(orgID),
		UserID:         ulidToPgUUID(userID),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) OrganizationMembersByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.OrganizationMember, error) {
	rows, err := s.q.OrganizationMembersByOrg(ctx, ulidToPgUUID(orgID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.OrganizationMember, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToOrgMember(r))
	}
	return out, nil
}

func (s *Store) OrganizationsByUser(ctx context.Context, userID theauth.ULID) ([]theauth.Organization, error) {
	rows, err := s.q.OrganizationsByUser(ctx, ulidToPgUUID(userID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.Organization, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToOrganization(r))
	}
	return out, nil
}

func (s *Store) OrganizationMemberRole(ctx context.Context, orgID, userID theauth.ULID) (string, error) {
	role, err := s.q.OrganizationMemberRole(ctx, sqlcgen.OrganizationMemberRoleParams{
		OrganizationID: ulidToPgUUID(orgID),
		UserID:         ulidToPgUUID(userID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrNotFound
		}
		return "", err
	}
	return role, nil
}

func (s *Store) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	var pgOrgID pgtype.UUID
	if orgID != nil {
		pgOrgID = ulidToPgUUID(*orgID)
	}
	affected, err := s.q.SetSessionActiveOrganization(ctx, sqlcgen.SetSessionActiveOrganizationParams{
		ID:                   ulidToPgUUID(sessionID),
		ActiveOrganizationID: pgOrgID,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- SAML connections ----------

func rowToSAMLConnection(r sqlcgen.SamlConnection) theauth.SAMLConnection {
	var amap theauth.SAMLAttributeMap
	_ = json.Unmarshal(r.AttributeMap, &amap)
	return theauth.SAMLConnection{
		ID:             pgUUIDToULID(r.ID),
		OrganizationID: pgUUIDToULID(r.OrganizationID),
		IdPEntityID:    r.IdpEntityID,
		IdPSSOURL:      r.IdpSsoUrl,
		IdPX509Cert:    r.IdpX509Cert,
		SPEntityID:     r.SpEntityID,
		SPACSURL:       r.SpAcsUrl,
		AttributeMap:   amap,
		CreatedAt:      tsToTime(r.CreatedAt),
		UpdatedAt:      tsToTime(r.UpdatedAt),
	}
}

func (s *Store) InsertSAMLConnection(ctx context.Context, c theauth.SAMLConnection) (theauth.SAMLConnection, error) {
	amap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	row, err := s.q.InsertSAMLConnection(ctx, sqlcgen.InsertSAMLConnectionParams{
		ID:             ulidToPgUUID(c.ID),
		OrganizationID: ulidToPgUUID(c.OrganizationID),
		IdpEntityID:    c.IdPEntityID,
		IdpSsoUrl:      c.IdPSSOURL,
		IdpX509Cert:    c.IdPX509Cert,
		SpEntityID:     c.SPEntityID,
		SpAcsUrl:       c.SPACSURL,
		AttributeMap:   amap,
		CreatedAt:      timeToTs(c.CreatedAt),
		UpdatedAt:      timeToTs(c.UpdatedAt),
	})
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	return rowToSAMLConnection(row), nil
}

func (s *Store) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	amap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return err
	}
	affected, err := s.q.UpdateSAMLConnection(ctx, sqlcgen.UpdateSAMLConnectionParams{
		ID:           ulidToPgUUID(c.ID),
		IdpEntityID:  c.IdPEntityID,
		IdpSsoUrl:    c.IdPSSOURL,
		IdpX509Cert:  c.IdPX509Cert,
		SpEntityID:   c.SPEntityID,
		SpAcsUrl:     c.SPACSURL,
		AttributeMap: amap,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteSAMLConnection(ctx context.Context, id theauth.ULID) error {
	affected, err := s.q.DeleteSAMLConnection(ctx, ulidToPgUUID(id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) SAMLConnectionByID(ctx context.Context, id theauth.ULID) (*theauth.SAMLConnection, error) {
	row, err := s.q.SAMLConnectionByID(ctx, ulidToPgUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	c := rowToSAMLConnection(row)
	return &c, nil
}

func (s *Store) SAMLConnectionsByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SAMLConnection, error) {
	rows, err := s.q.SAMLConnectionsByOrg(ctx, ulidToPgUUID(orgID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.SAMLConnection, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToSAMLConnection(r))
	}
	return out, nil
}

// ---------- SAML identities ----------

func rowToSAMLIdentity(r sqlcgen.SamlIdentity) theauth.SAMLIdentity {
	return theauth.SAMLIdentity{
		ID:           pgUUIDToULID(r.ID),
		ConnectionID: pgUUIDToULID(r.ConnectionID),
		UserID:       pgUUIDToULID(r.UserID),
		NameID:       r.NameID,
		NameIDFormat: r.NameIDFormat,
		LastLoginAt:  tsToTimePtr(r.LastLoginAt),
		CreatedAt:    tsToTime(r.CreatedAt),
	}
}

func (s *Store) UpsertSAMLIdentity(ctx context.Context, i theauth.SAMLIdentity) (theauth.SAMLIdentity, error) {
	created := i.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	row, err := s.q.UpsertSAMLIdentity(ctx, sqlcgen.UpsertSAMLIdentityParams{
		ID:           ulidToPgUUID(i.ID),
		ConnectionID: ulidToPgUUID(i.ConnectionID),
		UserID:       ulidToPgUUID(i.UserID),
		NameID:       i.NameID,
		NameIDFormat: i.NameIDFormat,
		CreatedAt:    timeToTs(created),
	})
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	return rowToSAMLIdentity(row), nil
}

func (s *Store) SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID theauth.ULID, nameID string) (*theauth.SAMLIdentity, error) {
	row, err := s.q.SAMLIdentityByConnectionAndNameID(ctx, sqlcgen.SAMLIdentityByConnectionAndNameIDParams{
		ConnectionID: ulidToPgUUID(connectionID),
		NameID:       nameID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	i := rowToSAMLIdentity(row)
	return &i, nil
}

func (s *Store) TouchSAMLIdentityLastLogin(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.q.TouchSAMLIdentityLastLogin(ctx, sqlcgen.TouchSAMLIdentityLastLoginParams{
		ID:          ulidToPgUUID(id),
		LastLoginAt: timeToTs(at),
	})
}

// ---------- SCIM tokens ----------

func rowToSCIMToken(r sqlcgen.ScimToken) theauth.SCIMToken {
	return theauth.SCIMToken{
		ID:             pgUUIDToULID(r.ID),
		OrganizationID: pgUUIDToULID(r.OrganizationID),
		TokenHash:      r.TokenHash,
		Name:           r.Name,
		CreatedAt:      tsToTime(r.CreatedAt),
		LastUsedAt:     tsToTimePtr(r.LastUsedAt),
		RevokedAt:      tsToTimePtr(r.RevokedAt),
	}
}

func (s *Store) InsertSCIMToken(ctx context.Context, t theauth.SCIMToken) (theauth.SCIMToken, error) {
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	row, err := s.q.InsertSCIMToken(ctx, sqlcgen.InsertSCIMTokenParams{
		ID:             ulidToPgUUID(t.ID),
		OrganizationID: ulidToPgUUID(t.OrganizationID),
		TokenHash:      t.TokenHash,
		Name:           t.Name,
		CreatedAt:      timeToTs(created),
	})
	if err != nil {
		return theauth.SCIMToken{}, err
	}
	return rowToSCIMToken(row), nil
}

func (s *Store) SCIMTokenByHash(ctx context.Context, hash []byte) (*theauth.SCIMToken, error) {
	row, err := s.q.SCIMTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	t := rowToSCIMToken(row)
	return &t, nil
}

func (s *Store) SCIMTokensByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SCIMToken, error) {
	rows, err := s.q.SCIMTokensByOrg(ctx, ulidToPgUUID(orgID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.SCIMToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToSCIMToken(r))
	}
	return out, nil
}

func (s *Store) RevokeSCIMTokenByID(ctx context.Context, id theauth.ULID, at time.Time) error {
	affected, err := s.q.RevokeSCIMTokenByID(ctx, sqlcgen.RevokeSCIMTokenByIDParams{
		ID:        ulidToPgUUID(id),
		RevokedAt: timeToTs(at),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) TouchSCIMTokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.q.TouchSCIMTokenLastUsed(ctx, sqlcgen.TouchSCIMTokenLastUsedParams{
		ID:         ulidToPgUUID(id),
		LastUsedAt: timeToTs(at),
	})
}

// ---------- SCIM scoped user/group reads + user update ----------

func rowToUserV07(r sqlcgen.User) theauth.User {
	u := rowToUser(r)
	u.ExternalID = r.ExternalID
	u.GivenName = r.GivenName
	u.FamilyName = r.FamilyName
	u.DisplayName = r.DisplayName
	return u
}

func (s *Store) ListUsersByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMUserFilter) ([]theauth.User, int, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.q.ListUsersByOrganization(ctx, sqlcgen.ListUsersByOrganizationParams{
		OrganizationID: ulidToPgUUID(orgID),
		UserName:       filter.UserName,
		ExternalID:     filter.ExternalID,
		Email:          filter.Email,
		OffsetN:        int32(offset),
		LimitN:         int32(limit),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.q.CountUsersByOrganization(ctx, sqlcgen.CountUsersByOrganizationParams{
		OrganizationID: ulidToPgUUID(orgID),
		UserName:       filter.UserName,
		ExternalID:     filter.ExternalID,
		Email:          filter.Email,
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]theauth.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToUserV07(r))
	}
	return out, int(total), nil
}

func (s *Store) ListGroupsByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMGroupFilter) ([]theauth.Group, int, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.q.ListGroupsByOrganization(ctx, sqlcgen.ListGroupsByOrganizationParams{
		OrganizationID: ulidToPgUUID(orgID),
		DisplayName:    filter.DisplayName,
		ExternalID:     filter.ExternalID,
		OffsetN:        int32(offset),
		LimitN:         int32(limit),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.q.CountGroupsByOrganization(ctx, sqlcgen.CountGroupsByOrganizationParams{
		OrganizationID: ulidToPgUUID(orgID),
		DisplayName:    filter.DisplayName,
		ExternalID:     filter.ExternalID,
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]theauth.Group, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToGroup(r))
	}
	return out, int(total), nil
}

func (s *Store) UserByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.User, error) {
	if externalID == "" {
		return nil, storage.ErrNotFound
	}
	row, err := s.q.UserByExternalIDInOrg(ctx, sqlcgen.UserByExternalIDInOrgParams{
		OrganizationID: ulidToPgUUID(orgID),
		ExternalID:     externalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	u := rowToUserV07(row)
	return &u, nil
}

func (s *Store) UpdateUserSCIM(ctx context.Context, u theauth.User) error {
	affected, err := s.q.UpdateUserSCIM(ctx, sqlcgen.UpdateUserSCIMParams{
		ID:          ulidToPgUUID(u.ID),
		Email:       u.Email,
		Name:        u.Name,
		AvatarUrl:   u.AvatarURL,
		ExternalID:  u.ExternalID,
		GivenName:   u.GivenName,
		FamilyName:  u.FamilyName,
		DisplayName: u.DisplayName,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- Groups ----------

func rowToGroup(r sqlcgen.Group) theauth.Group {
	ext := ""
	if r.ExternalID != nil {
		ext = *r.ExternalID
	}
	return theauth.Group{
		ID:             pgUUIDToULID(r.ID),
		OrganizationID: pgUUIDToULID(r.OrganizationID),
		DisplayName:    r.DisplayName,
		ExternalID:     ext,
		CreatedAt:      tsToTime(r.CreatedAt),
		UpdatedAt:      tsToTime(r.UpdatedAt),
	}
}

func (s *Store) InsertGroup(ctx context.Context, g theauth.Group) (theauth.Group, error) {
	var ext *string
	if g.ExternalID != "" {
		v := g.ExternalID
		ext = &v
	}
	created := g.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	row, err := s.q.InsertGroup(ctx, sqlcgen.InsertGroupParams{
		ID:             ulidToPgUUID(g.ID),
		OrganizationID: ulidToPgUUID(g.OrganizationID),
		DisplayName:    g.DisplayName,
		ExternalID:     ext,
		CreatedAt:      timeToTs(created),
	})
	if err != nil {
		return theauth.Group{}, err
	}
	return rowToGroup(row), nil
}

func (s *Store) GroupByID(ctx context.Context, id theauth.ULID) (*theauth.Group, error) {
	row, err := s.q.GroupByID(ctx, ulidToPgUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	g := rowToGroup(row)
	return &g, nil
}

func (s *Store) GroupByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.Group, error) {
	if externalID == "" {
		return nil, storage.ErrNotFound
	}
	row, err := s.q.GroupByExternalIDInOrg(ctx, sqlcgen.GroupByExternalIDInOrgParams{
		OrganizationID: ulidToPgUUID(orgID),
		ExternalID:     &externalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	g := rowToGroup(row)
	return &g, nil
}

func (s *Store) UpdateGroup(ctx context.Context, g theauth.Group) error {
	var ext *string
	if g.ExternalID != "" {
		v := g.ExternalID
		ext = &v
	}
	affected, err := s.q.UpdateGroup(ctx, sqlcgen.UpdateGroupParams{
		ID:          ulidToPgUUID(g.ID),
		DisplayName: g.DisplayName,
		ExternalID:  ext,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, id theauth.ULID) error {
	affected, err := s.q.DeleteGroup(ctx, ulidToPgUUID(id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) SetGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if err := q.DeleteAllGroupMembers(ctx, ulidToPgUUID(groupID)); err != nil {
		return err
	}
	for _, u := range userIDs {
		if err := q.InsertGroupMember(ctx, sqlcgen.InsertGroupMemberParams{
			GroupID: ulidToPgUUID(groupID),
			UserID:  ulidToPgUUID(u),
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) AddGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	for _, u := range userIDs {
		if err := s.q.InsertGroupMember(ctx, sqlcgen.InsertGroupMemberParams{
			GroupID: ulidToPgUUID(groupID),
			UserID:  ulidToPgUUID(u),
		}); err != nil {
			// ON CONFLICT DO NOTHING is in the query; an error here is real.
			return err
		}
	}
	return nil
}

func (s *Store) RemoveGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	for _, u := range userIDs {
		if err := s.q.DeleteGroupMember(ctx, sqlcgen.DeleteGroupMemberParams{
			GroupID: ulidToPgUUID(groupID),
			UserID:  ulidToPgUUID(u),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GroupMembers(ctx context.Context, groupID theauth.ULID) ([]theauth.ULID, error) {
	rows, err := s.q.GroupMembersByGroupID(ctx, ulidToPgUUID(groupID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.ULID, 0, len(rows))
	for _, r := range rows {
		out = append(out, pgUUIDToULID(r))
	}
	return out, nil
}

// isUniqueViolation checks if err is a pgx unique-constraint violation on the
// named constraint. We avoid pulling in pgconn just for this; the error
// stringification is stable across pgx v5.
func isUniqueViolation(err error, constraint string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLSTATE 23505") &&
		(constraint == "" || strings.Contains(msg, constraint))
}

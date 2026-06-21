package memory

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// v0.7: multi-tenancy + SAML + SCIM additive state. Kept in a separate
// file from memory.go to keep that adapter under the 500-LOC budget.
//
// All maps live under the Store struct via the v07 init in New(); we hang
// them off a sidecar map initialised lazily so the existing Store{} literal
// in tests does not need a code change.

type v07State struct {
	orgs            map[theauth.ULID]theauth.Organization
	orgsBySlug      map[string]theauth.ULID
	members         map[memberKey]theauth.OrganizationMember
	samlConnections map[theauth.ULID]theauth.SAMLConnection
	samlIdentities  map[theauth.ULID]theauth.SAMLIdentity
	scimTokens      map[theauth.ULID]theauth.SCIMToken
	groups          map[theauth.ULID]theauth.Group
	groupMembers    map[theauth.ULID]map[theauth.ULID]struct{} // groupID -> set of userID
}

type memberKey struct {
	orgID  theauth.ULID
	userID theauth.ULID
}

func (s *Store) ensureV07() *v07State {
	if s.v07 == nil {
		s.v07 = &v07State{
			orgs:            map[theauth.ULID]theauth.Organization{},
			orgsBySlug:      map[string]theauth.ULID{},
			members:         map[memberKey]theauth.OrganizationMember{},
			samlConnections: map[theauth.ULID]theauth.SAMLConnection{},
			samlIdentities:  map[theauth.ULID]theauth.SAMLIdentity{},
			scimTokens:      map[theauth.ULID]theauth.SCIMToken{},
			groups:          map[theauth.ULID]theauth.Group{},
			groupMembers:    map[theauth.ULID]map[theauth.ULID]struct{}{},
		}
	}
	return s.v07
}

// ---------- Organizations ----------

func (s *Store) InsertOrganization(_ context.Context, o theauth.Organization) (theauth.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	slug := strings.ToLower(o.Slug)
	if _, dup := v.orgsBySlug[slug]; dup {
		return theauth.Organization{}, theauth.ErrSlugTaken
	}
	o.Slug = slug
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now()
	}
	if o.UpdatedAt.IsZero() {
		o.UpdatedAt = o.CreatedAt
	}
	v.orgs[o.ID] = o
	v.orgsBySlug[slug] = o.ID
	return o, nil
}

func (s *Store) OrganizationByID(_ context.Context, id theauth.ULID) (*theauth.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	o, ok := v.orgs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := o
	return &cp, nil
}

func (s *Store) OrganizationBySlug(_ context.Context, slug string) (*theauth.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	id, ok := v.orgsBySlug[strings.ToLower(slug)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	o := v.orgs[id]
	cp := o
	return &cp, nil
}

func (s *Store) UpdateOrganization(_ context.Context, o theauth.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	existing, ok := v.orgs[o.ID]
	if !ok {
		return storage.ErrNotFound
	}
	newSlug := strings.ToLower(o.Slug)
	if newSlug != existing.Slug {
		if _, dup := v.orgsBySlug[newSlug]; dup {
			return theauth.ErrSlugTaken
		}
		delete(v.orgsBySlug, existing.Slug)
		v.orgsBySlug[newSlug] = o.ID
	}
	o.Slug = newSlug
	o.CreatedAt = existing.CreatedAt
	o.UpdatedAt = time.Now()
	v.orgs[o.ID] = o
	return nil
}

func (s *Store) DeleteOrganization(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	o, ok := v.orgs[id]
	if !ok {
		return storage.ErrNotFound
	}
	delete(v.orgs, id)
	delete(v.orgsBySlug, o.Slug)
	// Cascade equivalents
	for k := range v.members {
		if k.orgID == id {
			delete(v.members, k)
		}
	}
	for connID, conn := range v.samlConnections {
		if conn.OrganizationID == id {
			delete(v.samlConnections, connID)
			for identID, ident := range v.samlIdentities {
				if ident.ConnectionID == connID {
					delete(v.samlIdentities, identID)
				}
			}
		}
	}
	for tokenID, tok := range v.scimTokens {
		if tok.OrganizationID == id {
			delete(v.scimTokens, tokenID)
		}
	}
	for groupID, g := range v.groups {
		if g.OrganizationID == id {
			delete(v.groups, groupID)
			delete(v.groupMembers, groupID)
		}
	}
	// ON DELETE SET NULL on sessions.active_organization_id
	for sid, sess := range s.sessions {
		if sess.ActiveOrganizationID != nil && *sess.ActiveOrganizationID == id {
			sess.ActiveOrganizationID = nil
			s.sessions[sid] = sess
		}
	}
	return nil
}

func (s *Store) UpsertOrganizationMember(_ context.Context, m theauth.OrganizationMember) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.orgs[m.OrganizationID]; !ok {
		return storage.ErrNotFound
	}
	if _, ok := s.users[m.UserID]; !ok {
		return storage.ErrNotFound
	}
	key := memberKey{orgID: m.OrganizationID, userID: m.UserID}
	if existing, ok := v.members[key]; ok {
		existing.Role = m.Role
		v.members[key] = existing
		return nil
	}
	if m.JoinedAt.IsZero() {
		m.JoinedAt = time.Now()
	}
	v.members[key] = m
	return nil
}

func (s *Store) DeleteOrganizationMember(_ context.Context, orgID, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	key := memberKey{orgID: orgID, userID: userID}
	if _, ok := v.members[key]; !ok {
		return storage.ErrNotFound
	}
	delete(v.members, key)
	return nil
}

func (s *Store) OrganizationMembersByOrg(_ context.Context, orgID theauth.ULID) ([]theauth.OrganizationMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var out []theauth.OrganizationMember
	for _, m := range v.members {
		if m.OrganizationID == orgID {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JoinedAt.Before(out[j].JoinedAt) })
	return out, nil
}

func (s *Store) OrganizationsByUser(_ context.Context, userID theauth.ULID) ([]theauth.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var out []theauth.Organization
	for _, m := range v.members {
		if m.UserID == userID {
			if o, ok := v.orgs[m.OrganizationID]; ok {
				out = append(out, o)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) OrganizationMemberRole(_ context.Context, orgID, userID theauth.ULID) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	m, ok := v.members[memberKey{orgID: orgID, userID: userID}]
	if !ok {
		return "", storage.ErrNotFound
	}
	return m.Role, nil
}

func (s *Store) SetSessionActiveOrganization(_ context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return storage.ErrNotFound
	}
	if orgID != nil {
		v := s.ensureV07()
		if _, ok := v.orgs[*orgID]; !ok {
			return storage.ErrNotFound
		}
	}
	sess.ActiveOrganizationID = orgID
	s.sessions[sessionID] = sess
	return nil
}

// ---------- SAML ----------

func (s *Store) InsertSAMLConnection(_ context.Context, c theauth.SAMLConnection) (theauth.SAMLConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.orgs[c.OrganizationID]; !ok {
		return theauth.SAMLConnection{}, storage.ErrNotFound
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	c.UpdatedAt = c.CreatedAt
	v.samlConnections[c.ID] = c
	return c, nil
}

func (s *Store) UpdateSAMLConnectionRow(_ context.Context, c theauth.SAMLConnection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	existing, ok := v.samlConnections[c.ID]
	if !ok {
		return storage.ErrNotFound
	}
	c.CreatedAt = existing.CreatedAt
	c.UpdatedAt = time.Now()
	v.samlConnections[c.ID] = c
	return nil
}

func (s *Store) DeleteSAMLConnection(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.samlConnections[id]; !ok {
		return storage.ErrNotFound
	}
	delete(v.samlConnections, id)
	for identID, ident := range v.samlIdentities {
		if ident.ConnectionID == id {
			delete(v.samlIdentities, identID)
		}
	}
	return nil
}

func (s *Store) SAMLConnectionByID(_ context.Context, id theauth.ULID) (*theauth.SAMLConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	c, ok := v.samlConnections[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := c
	return &cp, nil
}

func (s *Store) SAMLConnectionsByOrg(_ context.Context, orgID theauth.ULID) ([]theauth.SAMLConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var out []theauth.SAMLConnection
	for _, c := range v.samlConnections {
		if c.OrganizationID == orgID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) UpsertSAMLIdentity(_ context.Context, i theauth.SAMLIdentity) (theauth.SAMLIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	for id, existing := range v.samlIdentities {
		if existing.ConnectionID == i.ConnectionID && existing.NameID == i.NameID {
			existing.UserID = i.UserID
			existing.NameIDFormat = i.NameIDFormat
			v.samlIdentities[id] = existing
			return existing, nil
		}
	}
	if i.CreatedAt.IsZero() {
		i.CreatedAt = time.Now()
	}
	v.samlIdentities[i.ID] = i
	return i, nil
}

func (s *Store) SAMLIdentityByConnectionAndNameID(_ context.Context, connectionID theauth.ULID, nameID string) (*theauth.SAMLIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	for _, i := range v.samlIdentities {
		if i.ConnectionID == connectionID && i.NameID == nameID {
			cp := i
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) TouchSAMLIdentityLastLogin(_ context.Context, id theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	i, ok := v.samlIdentities[id]
	if !ok {
		return storage.ErrNotFound
	}
	t := at
	i.LastLoginAt = &t
	v.samlIdentities[id] = i
	return nil
}

// ---------- SCIM tokens ----------

func (s *Store) InsertSCIMToken(_ context.Context, t theauth.SCIMToken) (theauth.SCIMToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.orgs[t.OrganizationID]; !ok {
		return theauth.SCIMToken{}, storage.ErrNotFound
	}
	for _, existing := range v.scimTokens {
		if bytes.Equal(existing.TokenHash, t.TokenHash) {
			return theauth.SCIMToken{}, storage.ErrNotFound
		}
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	v.scimTokens[t.ID] = t
	return t, nil
}

func (s *Store) SCIMTokenByHash(_ context.Context, hash []byte) (*theauth.SCIMToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	for _, t := range v.scimTokens {
		if bytes.Equal(t.TokenHash, hash) {
			cp := t
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) SCIMTokensByOrg(_ context.Context, orgID theauth.ULID) ([]theauth.SCIMToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var out []theauth.SCIMToken
	for _, t := range v.scimTokens {
		if t.OrganizationID == orgID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RevokeSCIMTokenByID(_ context.Context, id theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	t, ok := v.scimTokens[id]
	if !ok {
		return storage.ErrNotFound
	}
	tt := at
	t.RevokedAt = &tt
	v.scimTokens[id] = t
	return nil
}

func (s *Store) TouchSCIMTokenLastUsed(_ context.Context, id theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	t, ok := v.scimTokens[id]
	if !ok {
		return storage.ErrNotFound
	}
	tt := at
	t.LastUsedAt = &tt
	v.scimTokens[id] = t
	return nil
}

// ---------- SCIM scoped reads + user update ----------

func (s *Store) ListUsersByOrganization(_ context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMUserFilter) ([]theauth.User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var all []theauth.User
	for _, m := range v.members {
		if m.OrganizationID != orgID {
			continue
		}
		u, ok := s.users[m.UserID]
		if !ok {
			continue
		}
		if filter.UserName != "" && !strings.EqualFold(u.Email, filter.UserName) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.Before(all[j].CreatedAt) })
	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (s *Store) ListGroupsByOrganization(_ context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMGroupFilter) ([]theauth.Group, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	var all []theauth.Group
	for _, g := range v.groups {
		if g.OrganizationID != orgID {
			continue
		}
		if filter.DisplayName != "" && g.DisplayName != filter.DisplayName {
			continue
		}
		if filter.ExternalID != "" && g.ExternalID != filter.ExternalID {
			continue
		}
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.Before(all[j].CreatedAt) })
	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (s *Store) UserByExternalIDInOrg(_ context.Context, orgID theauth.ULID, externalID string) (*theauth.User, error) {
	if externalID == "" {
		return nil, storage.ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	for _, m := range v.members {
		if m.OrganizationID != orgID {
			continue
		}
		u, ok := s.users[m.UserID]
		if !ok {
			continue
		}
		if u.ExternalID == externalID {
			cp := u
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UpdateUserSCIM(_ context.Context, u theauth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[u.ID]
	if !ok {
		return storage.ErrNotFound
	}
	existing.Email = u.Email
	existing.Name = u.Name
	existing.AvatarURL = u.AvatarURL
	existing.ExternalID = u.ExternalID
	existing.GivenName = u.GivenName
	existing.FamilyName = u.FamilyName
	existing.DisplayName = u.DisplayName
	existing.UpdatedAt = time.Now()
	s.users[u.ID] = existing
	return nil
}

// ---------- Groups ----------

func (s *Store) InsertGroup(_ context.Context, g theauth.Group) (theauth.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.orgs[g.OrganizationID]; !ok {
		return theauth.Group{}, storage.ErrNotFound
	}
	for _, existing := range v.groups {
		if existing.OrganizationID == g.OrganizationID && existing.DisplayName == g.DisplayName {
			return theauth.Group{}, storage.ErrNotFound
		}
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now()
	}
	g.UpdatedAt = g.CreatedAt
	v.groups[g.ID] = g
	v.groupMembers[g.ID] = map[theauth.ULID]struct{}{}
	return g, nil
}

func (s *Store) GroupByID(_ context.Context, id theauth.ULID) (*theauth.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	g, ok := v.groups[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := g
	return &cp, nil
}

func (s *Store) GroupByExternalIDInOrg(_ context.Context, orgID theauth.ULID, externalID string) (*theauth.Group, error) {
	if externalID == "" {
		return nil, storage.ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	for _, g := range v.groups {
		if g.OrganizationID == orgID && g.ExternalID == externalID {
			cp := g
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UpdateGroup(_ context.Context, g theauth.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	existing, ok := v.groups[g.ID]
	if !ok {
		return storage.ErrNotFound
	}
	g.OrganizationID = existing.OrganizationID
	g.CreatedAt = existing.CreatedAt
	g.UpdatedAt = time.Now()
	v.groups[g.ID] = g
	return nil
}

func (s *Store) DeleteGroup(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.groups[id]; !ok {
		return storage.ErrNotFound
	}
	delete(v.groups, id)
	delete(v.groupMembers, id)
	return nil
}

func (s *Store) SetGroupMembers(_ context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.groups[groupID]; !ok {
		return storage.ErrNotFound
	}
	set := map[theauth.ULID]struct{}{}
	for _, u := range userIDs {
		if _, ok := s.users[u]; !ok {
			return storage.ErrNotFound
		}
		set[u] = struct{}{}
	}
	v.groupMembers[groupID] = set
	return nil
}

func (s *Store) AddGroupMembers(_ context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	if _, ok := v.groups[groupID]; !ok {
		return storage.ErrNotFound
	}
	set := v.groupMembers[groupID]
	if set == nil {
		set = map[theauth.ULID]struct{}{}
	}
	for _, u := range userIDs {
		if _, ok := s.users[u]; !ok {
			return storage.ErrNotFound
		}
		set[u] = struct{}{}
	}
	v.groupMembers[groupID] = set
	return nil
}

func (s *Store) RemoveGroupMembers(_ context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV07()
	set, ok := v.groupMembers[groupID]
	if !ok {
		return storage.ErrNotFound
	}
	for _, u := range userIDs {
		delete(set, u)
	}
	v.groupMembers[groupID] = set
	return nil
}

func (s *Store) GroupMembers(_ context.Context, groupID theauth.ULID) ([]theauth.ULID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV07()
	set, ok := v.groupMembers[groupID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := make([]theauth.ULID, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out, nil
}

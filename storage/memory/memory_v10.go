package memory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	"github.com/oklog/ulid/v2"
)

// ulidParseFn aliases the Crockford-base32 ULID parser. Wrapped here to
// keep the upstream import scope local to cursor decoding.
var ulidParseFn = ulid.Parse

// v1.0: RBAC + audit log additive state. Held in a sidecar so the existing
// New() literal stays compact; audit events live in a capped ring buffer so
// long-running tests never OOM.

const auditRingCap = 10000

type v10State struct {
	permissionsByID   map[theauth.ULID]theauth.Permission
	permissionsByName map[string]theauth.Permission
	roles             map[theauth.ULID]theauth.Role
	rolePerms         map[theauth.ULID]map[theauth.ULID]struct{} // roleID -> set of permID
	userRoles         map[memberKey]theauth.UserRole             // {userID, roleID} -> ur (memberKey re-used for the same 2-tuple shape)
	auditRing         []theauth.AuditEvent
	auditHead         int  // next write position
	auditWrapped      bool // ring has wrapped at least once

	mu sync.Mutex // protects audit ring writes only (Store.mu protects everything else)
}

func (s *Store) ensureV10() *v10State {
	if s.v10 == nil {
		s.v10 = &v10State{
			permissionsByID:   map[theauth.ULID]theauth.Permission{},
			permissionsByName: map[string]theauth.Permission{},
			roles:             map[theauth.ULID]theauth.Role{},
			rolePerms:         map[theauth.ULID]map[theauth.ULID]struct{}{},
			userRoles:         map[memberKey]theauth.UserRole{},
			auditRing:         make([]theauth.AuditEvent, 0, auditRingCap),
		}
	}
	return s.v10
}

// ---------- Permissions ----------

func (s *Store) InsertPermission(_ context.Context, p theauth.Permission) (theauth.Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	if existing, ok := v.permissionsByName[p.Name]; ok {
		return existing, nil
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	v.permissionsByID[p.ID] = p
	v.permissionsByName[p.Name] = p
	return p, nil
}

func (s *Store) PermissionByName(_ context.Context, name string) (*theauth.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	p, ok := v.permissionsByName[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := p
	return &cp, nil
}

func (s *Store) ListPermissions(_ context.Context) ([]theauth.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	out := make([]theauth.Permission, 0, len(v.permissionsByID))
	for _, p := range v.permissionsByID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---------- Roles ----------

func (s *Store) InsertRole(_ context.Context, r theauth.Role) (theauth.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	for _, existing := range v.roles {
		if rolesSameScope(existing, r) && existing.Name == r.Name {
			return theauth.Role{}, storage.ErrNotFound
		}
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	r.UpdatedAt = r.CreatedAt
	v.roles[r.ID] = r
	if _, ok := v.rolePerms[r.ID]; !ok {
		v.rolePerms[r.ID] = map[theauth.ULID]struct{}{}
	}
	return r, nil
}

func (s *Store) UpdateRoleRow(_ context.Context, r theauth.Role) (theauth.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	existing, ok := v.roles[r.ID]
	if !ok {
		return theauth.Role{}, storage.ErrNotFound
	}
	r.CreatedAt = existing.CreatedAt
	r.OrganizationID = existing.OrganizationID
	r.UpdatedAt = time.Now()
	v.roles[r.ID] = r
	return r, nil
}

func (s *Store) DeleteRole(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	if _, ok := v.roles[id]; !ok {
		return storage.ErrNotFound
	}
	delete(v.roles, id)
	delete(v.rolePerms, id)
	// Cascade user_roles for this role (memberKey re-uses the 2-tuple shape;
	// .orgID stores roleID for these entries).
	for k := range v.userRoles {
		if k.orgID == id {
			delete(v.userRoles, k)
		}
	}
	return nil
}

func (s *Store) RoleByID(_ context.Context, id theauth.ULID) (*theauth.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	r, ok := v.roles[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	r.Permissions = s.permsForRoleLocked(r.ID)
	return &r, nil
}

func (s *Store) RoleByOrgAndName(_ context.Context, orgID *theauth.ULID, name string) (*theauth.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	for _, r := range v.roles {
		if sameOrgPtr(r.OrganizationID, orgID) && r.Name == name {
			cp := r
			cp.Permissions = s.permsForRoleLocked(r.ID)
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) RolesByOrganization(_ context.Context, orgID *theauth.ULID) ([]theauth.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	var out []theauth.Role
	for _, r := range v.roles {
		if sameOrgPtr(r.OrganizationID, orgID) {
			r.Permissions = s.permsForRoleLocked(r.ID)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetRolePermissions(_ context.Context, roleID theauth.ULID, permissionIDs []theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	if _, ok := v.roles[roleID]; !ok {
		return storage.ErrNotFound
	}
	set := map[theauth.ULID]struct{}{}
	for _, id := range permissionIDs {
		if _, ok := v.permissionsByID[id]; !ok {
			return storage.ErrNotFound
		}
		set[id] = struct{}{}
	}
	v.rolePerms[roleID] = set
	return nil
}

func (s *Store) PermissionsByRole(_ context.Context, roleID theauth.ULID) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	if _, ok := v.roles[roleID]; !ok {
		return nil, storage.ErrNotFound
	}
	_ = v
	return s.permsForRoleLocked(roleID), nil
}

// permsForRoleLocked returns the permission name slice for one role.
// Caller must already hold s.mu (read or write).
func (s *Store) permsForRoleLocked(roleID theauth.ULID) []string {
	v := s.v10
	if v == nil {
		return nil
	}
	set := v.rolePerms[roleID]
	out := make([]string, 0, len(set))
	for permID := range set {
		if p, ok := v.permissionsByID[permID]; ok {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ---------- User-role grants ----------

func (s *Store) GrantUserRole(_ context.Context, ur theauth.UserRole) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	if _, ok := s.users[ur.UserID]; !ok {
		return storage.ErrNotFound
	}
	if _, ok := v.roles[ur.RoleID]; !ok {
		return storage.ErrNotFound
	}
	if ur.GrantedAt.IsZero() {
		ur.GrantedAt = time.Now()
	}
	k := memberKey{userID: ur.UserID, orgID: ur.RoleID} // re-uses the 2-tuple shape; .orgID stores roleID
	v.userRoles[k] = ur
	return nil
}

func (s *Store) RevokeUserRole(_ context.Context, userID, roleID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.ensureV10()
	k := memberKey{userID: userID, orgID: roleID}
	if _, ok := v.userRoles[k]; !ok {
		return storage.ErrNotFound
	}
	delete(v.userRoles, k)
	return nil
}

func (s *Store) RolesForUser(_ context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]theauth.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	var out []theauth.Role
	for k, _ := range v.userRoles {
		if k.userID != userID {
			continue
		}
		role, ok := v.roles[k.orgID] // .orgID holds roleID
		if !ok {
			continue
		}
		if !sameOrgPtr(role.OrganizationID, orgID) {
			continue
		}
		role.Permissions = s.permsForRoleLocked(role.ID)
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) PermissionsForUser(_ context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	set := map[string]struct{}{}
	for k := range v.userRoles {
		if k.userID != userID {
			continue
		}
		role, ok := v.roles[k.orgID]
		if !ok {
			continue
		}
		if !sameOrgPtr(role.OrganizationID, orgID) {
			continue
		}
		for _, p := range s.permsForRoleLocked(role.ID) {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) CountUsersWithPermissionInOrg(_ context.Context, orgID theauth.ULID, perm string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.ensureV10()
	users := map[theauth.ULID]struct{}{}
	for k := range v.userRoles {
		role, ok := v.roles[k.orgID]
		if !ok {
			continue
		}
		if role.OrganizationID == nil || *role.OrganizationID != orgID {
			continue
		}
		for _, p := range s.permsForRoleLocked(role.ID) {
			if p == perm {
				users[k.userID] = struct{}{}
				break
			}
		}
	}
	return len(users), nil
}

// ---------- Audit ----------

func (s *Store) InsertAuditEvents(_ context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	v := s.ensureV10()
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range events {
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		if len(v.auditRing) < auditRingCap {
			v.auditRing = append(v.auditRing, e)
			v.auditHead = len(v.auditRing) % auditRingCap
			continue
		}
		v.auditRing[v.auditHead] = e
		v.auditHead = (v.auditHead + 1) % auditRingCap
		v.auditWrapped = true
	}
	return nil
}

func (s *Store) QueryAuditEvents(_ context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	v := s.ensureV10()
	v.mu.Lock()
	snap := make([]theauth.AuditEvent, len(v.auditRing))
	copy(snap, v.auditRing)
	v.mu.Unlock()
	// Newest first.
	sort.Slice(snap, func(i, j int) bool {
		if !snap[i].CreatedAt.Equal(snap[j].CreatedAt) {
			return snap[i].CreatedAt.After(snap[j].CreatedAt)
		}
		return snap[i].ID.Compare(snap[j].ID) > 0
	})
	cursor := q.After
	var afterTS time.Time
	var afterID theauth.ULID
	if cursor != "" {
		ts, id, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		afterTS = ts
		afterID = id
	}
	out := []theauth.AuditEvent{}
	for _, e := range snap {
		if q.OrganizationID != nil {
			if e.OrganizationID == nil || *e.OrganizationID != *q.OrganizationID {
				continue
			}
		}
		if q.ActorUserID != nil {
			if e.ActorUserID == nil || *e.ActorUserID != *q.ActorUserID {
				continue
			}
		}
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		if q.TargetType != "" && e.TargetType != q.TargetType {
			continue
		}
		if q.TargetID != "" && e.TargetID != q.TargetID {
			continue
		}
		if q.Since != nil && e.CreatedAt.Before(*q.Since) {
			continue
		}
		if q.Until != nil && e.CreatedAt.After(*q.Until) {
			continue
		}
		if cursor != "" {
			if e.CreatedAt.After(afterTS) {
				continue
			}
			if e.CreatedAt.Equal(afterTS) && e.ID.Compare(afterID) >= 0 {
				continue
			}
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	var next string
	if q.Limit > 0 && len(out) == q.Limit {
		last := out[len(out)-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

// ---------- cursor codec (mirrors admin.Cursor) ----------

func encodeCursor(ts time.Time, id theauth.ULID) string {
	raw := strconv.FormatInt(ts.UnixMicro(), 10) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(s string) (time.Time, theauth.ULID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, theauth.ULID{}, errors.New("cursor format")
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor micros: %w", err)
	}
	id, err := ulidParseFn(parts[1])
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor ulid: %w", err)
	}
	return time.UnixMicro(micros), id, nil
}

// ---------- helpers ----------

func sameOrgPtr(a, b *theauth.ULID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func rolesSameScope(a, b theauth.Role) bool {
	return sameOrgPtr(a.OrganizationID, b.OrganizationID)
}

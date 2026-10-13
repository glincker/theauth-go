package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	admin "github.com/glincker/theauth-go/v2/internal/admin"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-chi/chi/v5"
)

type stubLifecycle struct {
	must     map[models.ULID]bool
	disabled map[models.ULID]bool
	deleted  []models.ULID
	err      error
}

func newStubLifecycle() *stubLifecycle {
	return &stubLifecycle{must: map[models.ULID]bool{}, disabled: map[models.ULID]bool{}}
}

func (s *stubLifecycle) SetMustChangePassword(_ context.Context, id models.ULID, v bool) error {
	s.must[id] = v
	return s.err
}

func (s *stubLifecycle) DisableUser(_ context.Context, id models.ULID) error {
	s.disabled[id] = true
	return s.err
}

func (s *stubLifecycle) EnableUser(_ context.Context, id models.ULID) error {
	s.disabled[id] = false
	return s.err
}

func (s *stubLifecycle) DeleteUser(_ context.Context, id models.ULID) error {
	s.deleted = append(s.deleted, id)
	return s.err
}

// lifecycleServer mounts the admin handler with a lifecycle stub. When super
// is true the caller holds the super_admin role.
func lifecycleServer(t *testing.T, life admin.Lifecycle, super bool) (*httptest.Server, *stubAdminStorage, models.ULID, *models.User, models.ULID) {
	t.Helper()
	store := newStubStorage()
	orgID := ulid.New()
	target := ulid.New()
	store.addUser(&models.User{ID: target, Email: "t@example.com"})
	store.addMember(orgID, target, models.OrgRoleMember)
	if super {
		store.addRole(&models.Role{ID: ulid.New(), Name: models.SystemRoleSuperAdmin})
	}
	caller := fakeAdminUser()
	sess := fakeAdminSession(orgID)
	h := admin.New(store, &stubRBAC{}, &stubAudit{}, "",
		func(*http.Request) (*models.User, bool) { return caller, true },
		func(*http.Request) (*models.Session, bool) { return sess, true })
	if life != nil {
		h.WithLifecycle(life)
	}
	pass := func(next http.Handler) http.Handler { return next }
	r := chi.NewRouter()
	h.Mount(r, pass, func(string) func(http.Handler) http.Handler { return pass }, nil)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, store, orgID, caller, target
}

func TestPatchUserMustChangePassword(t *testing.T) {
	life := newStubLifecycle()
	srv, _, orgID, _, target := lifecycleServer(t, life, false)
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+target.String()), []byte(`{"mustChangePassword":true}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !life.must[target] {
		t.Fatal("flag not set")
	}
}

func TestPatchUserDisableNeedsSuperAdmin(t *testing.T) {
	life := newStubLifecycle()
	srv, _, orgID, _, target := lifecycleServer(t, life, false)
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+target.String()), []byte(`{"disabled":true}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("org admin disable: status %d, want 403", resp.StatusCode)
	}
	if life.disabled[target] {
		t.Fatal("must not disable")
	}

	life2 := newStubLifecycle()
	srv2, _, orgID2, _, target2 := lifecycleServer(t, life2, true)
	resp = doAdminJSON(t, http.MethodPatch, adminURL(srv2, orgID2, "/users/"+target2.String()), []byte(`{"disabled":true}`))
	if resp.StatusCode != http.StatusOK || !life2.disabled[target2] {
		t.Fatalf("super admin disable: status %d disabled=%v", resp.StatusCode, life2.disabled[target2])
	}
	resp = doAdminJSON(t, http.MethodPatch, adminURL(srv2, orgID2, "/users/"+target2.String()), []byte(`{"disabled":false}`))
	if resp.StatusCode != http.StatusOK || life2.disabled[target2] {
		t.Fatalf("enable: status %d disabled=%v", resp.StatusCode, life2.disabled[target2])
	}
}

func TestPatchUserLifecycleFieldsWithoutLifecycle(t *testing.T) {
	srv, _, orgID, _, target := lifecycleServer(t, nil, true)
	resp := doAdminJSON(t, http.MethodPatch, adminURL(srv, orgID, "/users/"+target.String()), []byte(`{"disabled":true}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestDeleteUserAccount(t *testing.T) {
	t.Run("org admin refused", func(t *testing.T) {
		life := newStubLifecycle()
		srv, _, orgID, _, target := lifecycleServer(t, life, false)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+target.String()+"/account"), nil)
		if resp.StatusCode != http.StatusForbidden || len(life.deleted) != 0 {
			t.Fatalf("status %d deleted %v", resp.StatusCode, life.deleted)
		}
	})
	t.Run("super admin deletes", func(t *testing.T) {
		life := newStubLifecycle()
		srv, _, orgID, _, target := lifecycleServer(t, life, true)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+target.String()+"/account"), nil)
		if resp.StatusCode != http.StatusNoContent || len(life.deleted) != 1 || life.deleted[0] != target {
			t.Fatalf("status %d deleted %v", resp.StatusCode, life.deleted)
		}
	})
	t.Run("not in org", func(t *testing.T) {
		life := newStubLifecycle()
		srv, _, orgID, _, _ := lifecycleServer(t, life, true)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+ulid.New().String()+"/account"), nil)
		if resp.StatusCode != http.StatusNotFound || len(life.deleted) != 0 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("self refused", func(t *testing.T) {
		life := newStubLifecycle()
		srv, store, orgID, caller, _ := lifecycleServer(t, life, true)
		store.addMember(orgID, caller.ID, models.OrgRoleAdmin)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+caller.ID.String()+"/account"), nil)
		if resp.StatusCode != http.StatusBadRequest || len(life.deleted) != 0 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("last owner maps to 409", func(t *testing.T) {
		life := newStubLifecycle()
		life.err = models.ErrLastOwner
		srv, _, orgID, _, target := lifecycleServer(t, life, true)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+target.String()+"/account"), nil)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status %d, want 409", resp.StatusCode)
		}
	})
	t.Run("route absent without lifecycle", func(t *testing.T) {
		srv, _, orgID, _, target := lifecycleServer(t, nil, true)
		resp := doAdminJSON(t, http.MethodDelete, adminURL(srv, orgID, "/users/"+target.String()+"/account"), nil)
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

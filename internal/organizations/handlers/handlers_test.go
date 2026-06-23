// Package organizations_handlers_test contains direct HTTP-layer table tests
// for internal/organizations/handlers. Each sub-test mounts Handler onto a
// chi.Router via the package's Mount function and fires requests through
// httptest so the full handler chain is exercised without any root TheAuth
// state.
//
// All service calls are handled by stub implementations; no real database or
// network is required. Role checking, user/session injection, and service
// errors are all exercised by flipping fields on the stubs.
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/organizations/handlers"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// -----------------------------------------------------------------------------
// Stub implementations
// -----------------------------------------------------------------------------

// stubOrgService satisfies handlers.Service.
type stubOrgService struct {
	org          models.Organization
	orgs         []models.Organization
	err          error
	setActiveErr error
}

func (s *stubOrgService) Create(_ context.Context, name, slug string, _ models.ULID) (models.Organization, error) {
	if s.err != nil {
		return models.Organization{}, s.err
	}
	return models.Organization{
		ID:        ulid.New(),
		Name:      name,
		Slug:      slug,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (s *stubOrgService) ByID(_ context.Context, id models.ULID) (*models.Organization, error) {
	if s.err != nil {
		return nil, s.err
	}
	org := s.org
	org.ID = id
	return &org, nil
}

func (s *stubOrgService) AddMember(_ context.Context, _, _ models.ULID, _ string) error {
	return s.err
}

func (s *stubOrgService) RemoveMember(_ context.Context, _, _ models.ULID) error {
	return s.err
}

func (s *stubOrgService) ListUserOrganizations(_ context.Context, _ models.ULID) ([]models.Organization, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.orgs, nil
}

func (s *stubOrgService) SetActive(_ context.Context, _ models.ULID, _ *models.ULID) error {
	return s.setActiveErr
}

// stubRequireRole is a RoleChecker that allows or denies all requests.
type stubRequireRole struct{ allow bool }

func (rc *stubRequireRole) Check(w http.ResponseWriter, _ *http.Request, _, _ models.ULID, _ ...string) bool {
	if !rc.allow {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return rc.allow
}

// buildServer constructs a chi.Router with the organizations Handler mounted
// and returns an httptest.Server. user and sess may be nil to simulate
// unauthenticated requests. allowRole controls whether the requireRole check
// passes.
func buildServer(svc handlers.Service, user *models.User, sess *models.Session, allowRole bool) *httptest.Server {
	rc := &stubRequireRole{allow: allowRole}
	requireRole := handlers.RoleChecker(func(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID, roles ...string) bool {
		return rc.Check(w, r, orgID, userID, roles...)
	})
	userFromCtx := handlers.UserFromCtx(func(_ *http.Request) (*models.User, bool) {
		if user == nil {
			return nil, false
		}
		return user, true
	})
	sessFromCtx := handlers.SessionFromCtx(func(_ *http.Request) (*models.Session, bool) {
		if sess == nil {
			return nil, false
		}
		return sess, true
	})
	h := handlers.New(svc, requireRole, userFromCtx, sessFromCtx)
	r := chi.NewRouter()
	// requireAuth passthrough for test: always pass through.
	passthrough := func(next http.Handler) http.Handler { return next }
	h.Mount(r, passthrough, nil)
	return httptest.NewServer(r)
}

// fakeUser returns a test user with a fresh ULID.
func fakeUser() *models.User {
	return &models.User{
		ID:        ulid.New(),
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// fakeSession returns a test session with a fresh ULID whose active org
// equals orgID (or nil if orgID is zero).
func fakeSession(orgID *models.ULID) *models.Session {
	return &models.Session{
		ID:                   ulid.New(),
		UserID:               ulid.New(),
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(time.Hour),
		ActiveOrganizationID: orgID,
	}
}

// noRedirectClient stops at the first redirect.
var noRedirectClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// doJSON fires a request with a JSON body.
func doJSON(t *testing.T, method, url string, body []byte) *http.Response {
	t.Helper()
	var b *bytes.Reader
	if body != nil {
		b = bytes.NewReader(body)
	} else {
		b = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, b)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// -----------------------------------------------------------------------------
// POST /orgs -- create
// -----------------------------------------------------------------------------

// TestCreate_OK verifies that a valid create request returns 201 JSON.
func TestCreate_OK(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"name": "Acme Corp", "slug": "acme"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	var org models.Organization
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if org.Slug != "acme" {
		t.Fatalf("want slug=acme, got %q", org.Slug)
	}
}

// TestCreate_NoUser verifies that create without an authenticated user returns
// 401.
func TestCreate_NoUser(t *testing.T) {
	svc := &stubOrgService{}
	srv := buildServer(svc, nil, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"name": "X", "slug": "x"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

// TestCreate_BadJSON verifies that malformed JSON returns 400.
func TestCreate_BadJSON(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs", []byte("{bad json"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestCreate_SlugTaken verifies that a slug conflict returns 409.
func TestCreate_SlugTaken(t *testing.T) {
	svc := &stubOrgService{err: models.ErrSlugTaken}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"name": "Acme", "slug": "taken"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 for slug conflict, got %d", resp.StatusCode)
	}
}

// TestCreate_ServiceError verifies that a generic service error returns 400.
func TestCreate_ServiceError(t *testing.T) {
	svc := &stubOrgService{err: errors.New("storage failure")}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"name": "Acme", "slug": "acme2"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for service error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /orgs -- list
// -----------------------------------------------------------------------------

// TestList_OK verifies that list returns 200 JSON with the orgs slice.
func TestList_OK(t *testing.T) {
	org := models.Organization{ID: ulid.New(), Name: "Test", Slug: "test"}
	svc := &stubOrgService{orgs: []models.Organization{org}}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var orgs []models.Organization
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(orgs) != 1 {
		t.Fatalf("want 1 org, got %d", len(orgs))
	}
}

// TestList_NoUser verifies that list without an authenticated user returns 401.
func TestList_NoUser(t *testing.T) {
	svc := &stubOrgService{}
	srv := buildServer(svc, nil, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

// TestList_ServiceError verifies that a storage error returns 500.
func TestList_ServiceError(t *testing.T) {
	svc := &stubOrgService{err: errors.New("db down")}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500 for storage error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// GET /orgs/{id} -- get
// -----------------------------------------------------------------------------

// TestGet_OK verifies that get returns 200 JSON for a member.
func TestGet_OK(t *testing.T) {
	orgID := ulid.New()
	org := models.Organization{ID: orgID, Name: "Acme", Slug: "acme"}
	svc := &stubOrgService{org: org}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs/"+orgID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestGet_NonMember verifies that a failing role check returns 403.
func TestGet_NonMember(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, false) // role check fails
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs/"+orgID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for non-member, got %d", resp.StatusCode)
	}
}

// TestGet_NotFound verifies that a service error after role check returns 404.
func TestGet_NotFound(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{err: errors.New("not found")}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs/"+orgID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing org, got %d", resp.StatusCode)
	}
}

// TestGet_InvalidID verifies that a malformed ULID in the path returns 400.
func TestGet_InvalidID(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orgs/not-a-ulid", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid ULID, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// POST /orgs/{id}/activate -- activate
// -----------------------------------------------------------------------------

// TestActivate_OK verifies that activate returns 204 for a member.
func TestActivate_OK(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	sess := fakeSession(&orgID)
	srv := buildServer(svc, user, sess, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/activate", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestActivate_Forbidden verifies that a non-member cannot activate.
func TestActivate_Forbidden(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	sess := fakeSession(&orgID)
	srv := buildServer(svc, user, sess, false)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/activate", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestActivate_ServiceError verifies that a SetActive error returns 404.
func TestActivate_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{setActiveErr: errors.New("org not found")}
	user := fakeUser()
	sess := fakeSession(&orgID)
	srv := buildServer(svc, user, sess, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/activate", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 on activate error, got %d", resp.StatusCode)
	}
}

// TestActivate_InvalidID verifies that a bad ULID in the path returns 400.
func TestActivate_InvalidID(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	sess := fakeSession(nil)
	srv := buildServer(svc, user, sess, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/bad-id/activate", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad ULID, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// POST /orgs/clear-active -- clear active org
// -----------------------------------------------------------------------------

// TestClearActive_OK verifies that clear-active returns 204 when the session
// is present.
func TestClearActive_OK(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	orgID := ulid.New()
	sess := fakeSession(&orgID)
	srv := buildServer(svc, user, sess, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/clear-active", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestClearActive_NoSession verifies that clear-active without a session
// returns 401.
func TestClearActive_NoSession(t *testing.T) {
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/clear-active", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 when session missing, got %d", resp.StatusCode)
	}
}

// TestClearActive_ServiceError verifies that a SetActive error on clear-active
// returns 500.
func TestClearActive_ServiceError(t *testing.T) {
	svc := &stubOrgService{setActiveErr: errors.New("storage failure")}
	user := fakeUser()
	orgID := ulid.New()
	sess := fakeSession(&orgID)
	srv := buildServer(svc, user, sess, true)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/clear-active", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500 on clear-active error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// POST /orgs/{id}/members -- add member
// -----------------------------------------------------------------------------

// TestAddMember_OK verifies that adding a member returns 204.
func TestAddMember_OK(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"userId": memberID.String(), "role": "member"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/members", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestAddMember_Forbidden verifies that a non-admin cannot add members.
func TestAddMember_Forbidden(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, false)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"userId": memberID.String(), "role": "member"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/members", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestAddMember_BadUserID verifies that an invalid userId ULID returns 400.
func TestAddMember_BadUserID(t *testing.T) {
	orgID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"userId": "not-a-ulid", "role": "member"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/members", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid userId, got %d", resp.StatusCode)
	}
}

// TestAddMember_ServiceError verifies that a service error on AddMember
// returns 400.
func TestAddMember_ServiceError(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{err: errors.New("invalid role")}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"userId": memberID.String(), "role": "invalid"})
	resp := doJSON(t, http.MethodPost, srv.URL+"/orgs/"+orgID.String()+"/members", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 on service error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// DELETE /orgs/{id}/members/{userId} -- remove member
// -----------------------------------------------------------------------------

// TestRemoveMember_OK verifies that removing a member returns 204.
func TestRemoveMember_OK(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/orgs/"+orgID.String()+"/members/"+memberID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestRemoveMember_Forbidden verifies that a non-owner cannot remove members.
func TestRemoveMember_Forbidden(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{}
	user := fakeUser()
	srv := buildServer(svc, user, nil, false)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/orgs/"+orgID.String()+"/members/"+memberID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestRemoveMember_LastOwner verifies that ErrLastOwner maps to 409.
func TestRemoveMember_LastOwner(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{err: models.ErrLastOwner}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/orgs/"+orgID.String()+"/members/"+memberID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 for last owner, got %d", resp.StatusCode)
	}
}

// TestRemoveMember_NotFound verifies that a generic service error returns 404.
func TestRemoveMember_NotFound(t *testing.T) {
	orgID := ulid.New()
	memberID := ulid.New()
	svc := &stubOrgService{err: errors.New("not found")}
	user := fakeUser()
	srv := buildServer(svc, user, nil, true)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/orgs/"+orgID.String()+"/members/"+memberID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing member, got %d", resp.StatusCode)
	}
}

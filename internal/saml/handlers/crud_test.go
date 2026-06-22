// crud_test.go: direct HTTP-layer tests for the per-organization SAML
// connection CRUD endpoints (MountCRUD path). Uses the same external test
// package as handlers_test.go.
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/saml/handlers"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// -----------------------------------------------------------------------------
// CRUD stub implementations
// -----------------------------------------------------------------------------

// stubConnectionService satisfies handlers.ConnectionService.
type stubConnectionService struct {
	conn    models.SAMLConnection
	conns   []models.SAMLConnection
	err     error
	deleted bool
}

func (s *stubConnectionService) Create(_ context.Context, in handlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	if s.err != nil {
		return models.SAMLConnection{}, s.err
	}
	c := models.SAMLConnection{
		ID:             ulid.New(),
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
	s.conn = c
	return c, nil
}

func (s *stubConnectionService) Update(_ context.Context, id models.ULID, in handlers.SAMLConnectionInput) (models.SAMLConnection, error) {
	if s.err != nil {
		return models.SAMLConnection{}, s.err
	}
	s.conn.ID = id
	s.conn.IdPEntityID = in.IdPEntityID
	return s.conn, nil
}

func (s *stubConnectionService) Delete(_ context.Context, _ models.ULID) error {
	s.deleted = true
	return s.err
}

func (s *stubConnectionService) ByID(_ context.Context, _ models.ULID) (*models.SAMLConnection, error) {
	if s.err != nil {
		return nil, s.err
	}
	c := s.conn
	return &c, nil
}

func (s *stubConnectionService) List(_ context.Context, _ models.ULID) ([]models.SAMLConnection, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.conns, nil
}

// crudRoleChecker accepts all requests when allow=true, denies all when
// allow=false.
type crudRoleChecker struct{ allow bool }

func (c *crudRoleChecker) Check(w http.ResponseWriter, _ *http.Request, _, _ models.ULID, _ ...string) bool {
	if !c.allow {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return c.allow
}

// buildCRUDRouter builds a chi.Router with a CRUD-enabled Handler mounted
// under /orgs/{orgId}/saml/connections.
func buildCRUDRouter(
	connSvc handlers.ConnectionService,
	allow bool,
	user *models.User,
) *httptest.Server {
	svc := &stubService{} // SP-flow stubs (unused by CRUD endpoints)
	h := handlers.New(svc, handlers.SessionCookieConfig{
		Name: "theauth_sess", TTL: time.Hour,
	}, "/dashboard")

	rc := &crudRoleChecker{allow: allow}
	roleCheck := handlers.RoleChecker(func(w http.ResponseWriter, r *http.Request, orgID, userID models.ULID, roles ...string) bool {
		return rc.Check(w, r, orgID, userID, roles...)
	})
	userFromCtx := handlers.UserFromCtx(func(_ *http.Request) (*models.User, bool) {
		if user == nil {
			return nil, false
		}
		return user, true
	})
	h.AttachCRUD(connSvc, roleCheck, userFromCtx)

	r := chi.NewRouter()
	r.Route("/orgs/{orgId}/saml/connections", func(r chi.Router) {
		h.MountCRUD(r)
	})
	return httptest.NewServer(r)
}

// minimalConn returns a populated SAMLConnection for stub use.
func minimalConn(orgID models.ULID) models.SAMLConnection {
	return models.SAMLConnection{
		ID:             ulid.New(),
		OrganizationID: orgID,
		IdPEntityID:    "https://idp.example/metadata",
		IdPSSOURL:      "https://idp.example/sso",
		IdPX509Cert:    "CERT",
		SPEntityID:     "https://sp.example/saml",
		SPACSURL:       "https://sp.example/acs",
	}
}

// crudBody returns a JSON body for create/update requests.
func crudBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]string{
		"idpEntityId": "https://idp.example/metadata",
		"idpSsoUrl":   "https://idp.example/sso",
		"idpX509Cert": "CERT",
		"spEntityId":  "https://sp.example/saml",
		"spAcsUrl":    "https://sp.example/acs",
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// postCRUD fires a POST to the CRUD router.
func postCRUD(t *testing.T, srv *httptest.Server, orgID, path string, body []byte) *http.Response {
	t.Helper()
	url := srv.URL + "/orgs/" + orgID + "/saml/connections" + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// getCRUD fires a GET to the CRUD router.
func getCRUD(t *testing.T, srv *httptest.Server, orgID, path string) *http.Response {
	t.Helper()
	url := srv.URL + "/orgs/" + orgID + "/saml/connections" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// putCRUD fires a PUT to the CRUD router.
func putCRUD(t *testing.T, srv *httptest.Server, orgID, path string, body []byte) *http.Response {
	t.Helper()
	url := srv.URL + "/orgs/" + orgID + "/saml/connections" + path
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// deleteCRUD fires a DELETE to the CRUD router.
func deleteCRUD(t *testing.T, srv *httptest.Server, orgID, path string) *http.Response {
	t.Helper()
	url := srv.URL + "/orgs/" + orgID + "/saml/connections" + path
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// -----------------------------------------------------------------------------
// Create tests
// -----------------------------------------------------------------------------

// TestCRUDCreate_OK verifies that a valid POST returns 201 JSON.
func TestCRUDCreate_OK(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{}
	user := &models.User{ID: ulid.New(), Email: "admin@test.com"}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := postCRUD(t, srv, orgID.String(), "", crudBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
}

// TestCRUDCreate_BadJSON verifies that malformed JSON returns 400.
func TestCRUDCreate_BadJSON(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := postCRUD(t, srv, orgID.String(), "", []byte("{bad json"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestCRUDCreate_Forbidden verifies that a role check failure returns 403.
func TestCRUDCreate_Forbidden(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, false, user)
	defer srv.Close()

	resp := postCRUD(t, srv, orgID.String(), "", crudBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestCRUDCreate_ServiceError verifies that a service error returns 400.
func TestCRUDCreate_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{err: errStub}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := postCRUD(t, srv, orgID.String(), "", crudBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 on service error, got %d", resp.StatusCode)
	}
}

// errStub is a sentinel error for CRUD service stubs.
var errStub = errStubValue("stub error")

type errStubValue string

func (e errStubValue) Error() string { return string(e) }

// -----------------------------------------------------------------------------
// List tests
// -----------------------------------------------------------------------------

// TestCRUDList_OK verifies that GET / returns the connection list.
func TestCRUDList_OK(t *testing.T) {
	orgID := ulid.New()
	conn := minimalConn(orgID)
	svc := &stubConnectionService{conns: []models.SAMLConnection{conn}}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := getCRUD(t, srv, orgID.String(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var list []models.SAMLConnection
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 connection, got %d", len(list))
	}
}

// TestCRUDList_ServiceError verifies that a storage error returns 500.
func TestCRUDList_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{err: errStub}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := getCRUD(t, srv, orgID.String(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500 on storage error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Get tests
// -----------------------------------------------------------------------------

// TestCRUDGet_OK verifies that GET /{id} returns 200 JSON when the connection
// belongs to the requested org.
func TestCRUDGet_OK(t *testing.T) {
	orgID := ulid.New()
	conn := minimalConn(orgID)
	svc := &stubConnectionService{conn: conn}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := getCRUD(t, srv, orgID.String(), "/"+conn.ID.String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestCRUDGet_WrongOrg verifies that a connection belonging to a different
// org is not leaked (returns 404).
func TestCRUDGet_WrongOrg(t *testing.T) {
	orgID := ulid.New()
	otherOrg := ulid.New()
	conn := minimalConn(otherOrg)
	svc := &stubConnectionService{conn: conn}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := getCRUD(t, srv, orgID.String(), "/"+conn.ID.String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for wrong org, got %d", resp.StatusCode)
	}
}

// TestCRUDGet_ServiceError verifies that a storage error returns 404.
func TestCRUDGet_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{err: errStub}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := getCRUD(t, srv, orgID.String(), "/"+ulid.New().String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 on ByID error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Update tests
// -----------------------------------------------------------------------------

// TestCRUDUpdate_OK verifies that PUT /{id} returns 200 JSON.
func TestCRUDUpdate_OK(t *testing.T) {
	orgID := ulid.New()
	conn := minimalConn(orgID)
	svc := &stubConnectionService{conn: conn}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := putCRUD(t, srv, orgID.String(), "/"+conn.ID.String(), crudBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestCRUDUpdate_BadJSON verifies that malformed JSON returns 400.
func TestCRUDUpdate_BadJSON(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{conn: minimalConn(orgID)}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := putCRUD(t, srv, orgID.String(), "/"+ulid.New().String(), []byte("{bad"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// TestCRUDUpdate_ServiceError verifies that a service error returns 400.
func TestCRUDUpdate_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{err: errStub}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := putCRUD(t, srv, orgID.String(), "/"+ulid.New().String(), crudBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 on update error, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Delete tests
// -----------------------------------------------------------------------------

// TestCRUDDelete_OK verifies that DELETE /{id} returns 204.
func TestCRUDDelete_OK(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{conn: minimalConn(orgID)}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := deleteCRUD(t, srv, orgID.String(), "/"+ulid.New().String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
	if !svc.deleted {
		t.Fatal("Delete was not called on the service")
	}
}

// TestCRUDDelete_ServiceError verifies that a service error returns 404.
func TestCRUDDelete_ServiceError(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{err: errStub}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, true, user)
	defer srv.Close()

	resp := deleteCRUD(t, srv, orgID.String(), "/"+ulid.New().String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 on delete error, got %d", resp.StatusCode)
	}
}

// TestCRUDDelete_Forbidden verifies that a role-check failure returns 403.
func TestCRUDDelete_Forbidden(t *testing.T) {
	orgID := ulid.New()
	svc := &stubConnectionService{}
	user := &models.User{ID: ulid.New()}
	srv := buildCRUDRouter(svc, false, user)
	defer srv.Close()

	resp := deleteCRUD(t, srv, orgID.String(), "/"+ulid.New().String())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

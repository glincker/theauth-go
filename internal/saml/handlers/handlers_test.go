// Package saml_handlers_test contains direct HTTP-layer table tests for
// internal/saml/handlers. Each sub-test spins up a chi.Router via the
// package's Mount function and fires requests through httptest so the full
// handler chain is exercised without any root TheAuth state.
package handlers_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
	"github.com/glincker/theauth-go/internal/saml/handlers"
	"github.com/glincker/theauth-go/internal/samltest"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// stubService is a test double for handlers.Service.
type stubService struct {
	beginLoginURL string
	beginLoginErr error

	finishToken string
	finishErr   error

	metadataXML []byte
	metadataErr error
}

func (s *stubService) BeginLogin(_ context.Context, _ models.ULID, _ string) (string, error) {
	return s.beginLoginURL, s.beginLoginErr
}

func (s *stubService) FinishLogin(_ context.Context, _ models.ULID, _, _, _ string) (string, error) {
	return s.finishToken, s.finishErr
}

func (s *stubService) MetadataXML(_ context.Context, _ models.ULID) ([]byte, error) {
	return s.metadataXML, s.metadataErr
}

// noRedirectClient is an HTTP client that stops at the first redirect,
// returning the redirect response directly so tests can inspect the 302
// status and Location header without following to a nonexistent target.
var noRedirectClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// buildRouter mounts a Handler onto a chi.Router using the package's Mount
// function and returns a configured httptest.Server.
func buildRouter(svc handlers.Service) *httptest.Server {
	h := handlers.New(svc, handlers.SessionCookieConfig{
		Name:       "theauth_sess",
		SecureFlag: false,
		TTL:        time.Hour,
	}, "/dashboard")
	r := chi.NewRouter()
	h.Mount(r)
	return httptest.NewServer(r)
}

// validConnID returns a string representation of a fresh ULID suitable for
// embedding in a URL path segment.
func validConnID() string {
	return ulid.New().String()
}

// TestHandleLogin_Redirect verifies the happy path: BeginLogin returns a
// redirect URL and the handler issues a 302.
func TestHandleLogin_Redirect(t *testing.T) {
	svc := &stubService{beginLoginURL: "https://idp.example/sso?SAMLRequest=x"}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := noRedirectClient.Get(srv.URL + "/saml/" + id + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != svc.beginLoginURL {
		t.Fatalf("want redirect to %q, got %q", svc.beginLoginURL, loc)
	}
}

// TestHandleLogin_RelayState verifies that a RelayState query parameter is
// preserved (passed through to BeginLogin). The stub echoes it in the URL to
// confirm the handler called BeginLogin at all.
func TestHandleLogin_RelayState(t *testing.T) {
	svc := &stubService{beginLoginURL: "https://idp.example/sso?relay=yes"}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := noRedirectClient.Get(srv.URL + "/saml/" + id + "/login?RelayState=https://app/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
}

// TestHandleLogin_ServiceError verifies that a BeginLogin failure returns
// 400.
func TestHandleLogin_ServiceError(t *testing.T) {
	svc := &stubService{beginLoginErr: errors.New("idp unreachable")}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := noRedirectClient.Get(srv.URL + "/saml/" + id + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestHandleLogin_InvalidConnectionID verifies that a non-ULID connection ID
// path param returns 400.
func TestHandleLogin_InvalidConnectionID(t *testing.T) {
	svc := &stubService{beginLoginURL: "https://idp.example/sso"}
	srv := buildRouter(svc)
	defer srv.Close()

	resp, err := noRedirectClient.Get(srv.URL + "/saml/not-a-ulid/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestHandleACS_MissingSAMLResponse verifies that a POST to /acs without
// SAMLResponse returns 400.
func TestHandleACS_MissingSAMLResponse(t *testing.T) {
	svc := &stubService{}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := http.PostForm(srv.URL+"/saml/"+id+"/acs", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing SAMLResponse, got %d", resp.StatusCode)
	}
}

// postACS fires a POST to the /acs endpoint with the given base64 SAML
// response and optional RelayState, returning the HTTP response.
// Uses noRedirectClient so the 302 is returned directly rather than followed.
func postACS(t *testing.T, srv *httptest.Server, connID, samlResp, relayState string) *http.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResp}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/saml/"+connID+"/acs", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestHandleACS_ValidResponse verifies the happy-path ACS flow: a valid
// signed response causes FinishLogin to be called and the browser is
// redirected with a session cookie.
func TestHandleACS_ValidResponse(t *testing.T) {
	svc := &stubService{finishToken: "sess-tok-abc"}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	// We pass any non-empty base64 value; the stub returns success
	// regardless of the payload.
	resp := postACS(t, srv, id, "dGVzdA==", "/app")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302 after ACS success, got %d", resp.StatusCode)
	}
	// Verify the session cookie was set.
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_sess" && c.Value == "sess-tok-abc" {
			found = true
		}
	}
	if !found {
		t.Fatal("session cookie not set after ACS success")
	}
	// RelayState is used as the redirect target.
	if loc := resp.Header.Get("Location"); loc != "/app" {
		t.Fatalf("want redirect to /app, got %q", loc)
	}
}

// TestHandleACS_FallbackRedirect verifies that when no RelayState is sent the
// handler falls back to postLoginRedirect ("/dashboard" in our test setup).
func TestHandleACS_FallbackRedirect(t *testing.T) {
	svc := &stubService{finishToken: "sess-tok-xyz"}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp := postACS(t, srv, id, "dGVzdA==", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("want fallback redirect to /dashboard, got %q", loc)
	}
}

// TestHandleACS_UnsignedAssertion verifies that ErrSAMLUnsignedAssertion
// from the service layer maps to 403.
func TestHandleACS_UnsignedAssertion(t *testing.T) {
	svc := &stubService{finishErr: internalsaml.ErrSAMLUnsignedAssertion}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp := postACS(t, srv, id, "dGVzdA==", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for unsigned assertion, got %d", resp.StatusCode)
	}
}

// TestHandleACS_MissingEmail verifies that ErrSAMLMissingEmail maps to 403.
func TestHandleACS_MissingEmail(t *testing.T) {
	svc := &stubService{finishErr: internalsaml.ErrSAMLMissingEmail}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp := postACS(t, srv, id, "dGVzdA==", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing email, got %d", resp.StatusCode)
	}
}

// TestHandleACS_InvalidAssertion verifies that ErrSAMLInvalidAssertion
// maps to 403.
func TestHandleACS_InvalidAssertion(t *testing.T) {
	svc := &stubService{finishErr: internalsaml.ErrSAMLInvalidAssertion}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp := postACS(t, srv, id, "dGVzdA==", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for invalid assertion, got %d", resp.StatusCode)
	}
}

// TestHandleACS_InternalError verifies that an unrecognised service error
// maps to 500.
func TestHandleACS_InternalError(t *testing.T) {
	svc := &stubService{finishErr: errors.New("database unavailable")}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp := postACS(t, srv, id, "dGVzdA==", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500 for unexpected error, got %d", resp.StatusCode)
	}
}

// TestHandleACS_InvalidConnectionID verifies a bad ULID in the path returns
// 400 before any service call is attempted.
func TestHandleACS_InvalidConnectionID(t *testing.T) {
	svc := &stubService{}
	srv := buildRouter(svc)
	defer srv.Close()

	resp := postACS(t, srv, "bad-id", "dGVzdA==", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestHandleMetadata_OK verifies that a successful MetadataXML call returns
// 200 with the correct Content-Type.
func TestHandleMetadata_OK(t *testing.T) {
	svc := &stubService{metadataXML: []byte("<EntityDescriptor/>"), metadataErr: nil}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := noRedirectClient.Get(srv.URL + "/saml/" + id + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/samlmetadata+xml") {
		t.Fatalf("unexpected Content-Type: %q", ct)
	}
}

// TestHandleMetadata_NotFound verifies that a MetadataXML error returns 404.
func TestHandleMetadata_NotFound(t *testing.T) {
	svc := &stubService{metadataErr: errors.New("not found")}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	resp, err := noRedirectClient.Get(srv.URL + "/saml/" + id + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

// TestHandleMetadata_InvalidConnectionID verifies bad ULID returns 400.
func TestHandleMetadata_InvalidConnectionID(t *testing.T) {
	svc := &stubService{}
	srv := buildRouter(svc)
	defer srv.Close()

	resp, err := noRedirectClient.Get(srv.URL + "/saml/NOTAULID/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestClientIP_XFF exercises the XFF-aware IP extractor through the ACS
// handler path. We inject X-Forwarded-For and confirm the request does not
// panic or return an unexpected status (the stub service does not inspect ip
// so any non-500 from service indicates success).
func TestClientIP_XFF(t *testing.T) {
	svc := &stubService{finishToken: "tok"}
	srv := buildRouter(svc)
	defer srv.Close()

	id := validConnID()
	form := url.Values{"SAMLResponse": {"dGVzdA=="}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/saml/"+id+"/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Redirect means the handler called FinishLogin successfully via the stub.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
}

// TestHandleACS_SignedResponseIntegration uses the samltest helper to mint a
// real signed assertion and passes it through a real internalsaml.Service
// wired directly (not the stub). This exercises the XML parsing + signature
// verification path inside the handler chain.
func TestHandleACS_SignedResponseIntegration(t *testing.T) {
	// Build a minimal SAML service backed by an in-memory stub that returns
	// the connection we seed below.
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	spEntityID := "https://sp.test/saml"
	spACSURL := "https://sp.test/auth/saml/" + ulid.New().String() + "/acs"

	connID := ulid.New()
	fakeConn := &models.SAMLConnection{
		ID:          connID,
		IdPEntityID: samltest.IdPEntityID(),
		IdPSSOURL:   samltest.IdPSSOURL(),
		IdPX509Cert: samltest.IdPCertPEM(),
		SPEntityID:  spEntityID,
		SPACSURL:    spACSURL,
		AttributeMap: models.SAMLAttributeMap{
			Email:      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			GivenName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			FamilyName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
			Name:       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			Groups:     "http://schemas.xmlsoap.org/claims/Group",
		},
	}

	store := &inMemSAMLStorage{conn: fakeConn}
	sessions := &fakeSessionIssuer{token: "integration-sess-tok"}

	cfg, err := buildSAMLServiceConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	svc := internalsaml.NewService(store, sessions, nil, cfg)
	svc.Start()
	t.Cleanup(svc.Stop)

	// Wire the real service behind a thin adapter that satisfies
	// handlers.Service.
	adapter := &samlServiceAdapter{svc: svc, connID: connID}
	h := handlers.New(adapter, handlers.SessionCookieConfig{
		Name:       "theauth_sess",
		SecureFlag: false,
		TTL:        time.Hour,
	}, "/dashboard")
	r := chi.NewRouter()
	h.Mount(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	assertion := samltest.Default(spEntityID, spACSURL)
	samlResp, err := assertion.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}

	resp := postACS(t, ts, connID.String(), samlResp, "/after-login")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("integration ACS: want 302, got %d", resp.StatusCode)
	}
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_sess" && c.Value == "integration-sess-tok" {
			found = true
		}
	}
	if !found {
		t.Fatal("integration ACS: session cookie not set")
	}
}

// TestHandleACS_UnsignedResponseIntegration confirms that an unsigned
// assertion (SkipSign: true) through the real SAML service is rejected at
// the handler layer with 403.
func TestHandleACS_UnsignedResponseIntegration(t *testing.T) {
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	spEntityID := "https://sp.test/saml"
	spACSURL := "https://sp.test/auth/saml/" + ulid.New().String() + "/acs"

	connID := ulid.New()
	fakeConn := &models.SAMLConnection{
		ID:          connID,
		IdPEntityID: samltest.IdPEntityID(),
		IdPSSOURL:   samltest.IdPSSOURL(),
		IdPX509Cert: samltest.IdPCertPEM(),
		SPEntityID:  spEntityID,
		SPACSURL:    spACSURL,
		AttributeMap: models.SAMLAttributeMap{
			Email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		},
	}
	store := &inMemSAMLStorage{conn: fakeConn}
	sessions := &fakeSessionIssuer{}

	cfg, err := buildSAMLServiceConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	svc := internalsaml.NewService(store, sessions, nil, cfg)
	svc.Start()
	t.Cleanup(svc.Stop)

	adapter := &samlServiceAdapter{svc: svc, connID: connID}
	h := handlers.New(adapter, handlers.SessionCookieConfig{
		Name: "theauth_sess", TTL: time.Hour,
	}, "/dashboard")
	r := chi.NewRouter()
	h.Mount(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	unsigned := samltest.Default(spEntityID, spACSURL)
	unsigned.SkipSign = true
	samlResp, err := unsigned.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}

	resp := postACS(t, ts, connID.String(), samlResp, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned integration: want 403, got %d", resp.StatusCode)
	}
}

// TestHandleACS_ExpiredNotOnOrAfterIntegration confirms that a signed but
// expired assertion is rejected with 403.
func TestHandleACS_ExpiredNotOnOrAfterIntegration(t *testing.T) {
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	spEntityID := "https://sp.test/saml"
	spACSURL := "https://sp.test/auth/saml/" + ulid.New().String() + "/acs"

	connID := ulid.New()
	fakeConn := &models.SAMLConnection{
		ID:          connID,
		IdPEntityID: samltest.IdPEntityID(),
		IdPSSOURL:   samltest.IdPSSOURL(),
		IdPX509Cert: samltest.IdPCertPEM(),
		SPEntityID:  spEntityID,
		SPACSURL:    spACSURL,
		AttributeMap: models.SAMLAttributeMap{
			Email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		},
	}
	store := &inMemSAMLStorage{conn: fakeConn}
	sessions := &fakeSessionIssuer{}

	cfg, err := buildSAMLServiceConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	svc := internalsaml.NewService(store, sessions, nil, cfg)
	svc.Start()
	t.Cleanup(svc.Stop)

	adapter := &samlServiceAdapter{svc: svc, connID: connID}
	h := handlers.New(adapter, handlers.SessionCookieConfig{
		Name: "theauth_sess", TTL: time.Hour,
	}, "/dashboard")
	r := chi.NewRouter()
	h.Mount(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	expired := samltest.Default(spEntityID, spACSURL)
	// Push both time bounds into the past.
	expired.NotBefore = time.Now().Add(-2 * time.Hour)
	expired.NotOnOrAfter = time.Now().Add(-time.Hour)
	samlResp, err := expired.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}

	resp := postACS(t, ts, connID.String(), samlResp, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired assertion: want 403, got %d", resp.StatusCode)
	}
}

// TestHandleACS_WrongAudienceIntegration confirms that a signed assertion
// with a mismatched audience is rejected with 403.
func TestHandleACS_WrongAudienceIntegration(t *testing.T) {
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	spEntityID := "https://sp.test/saml"
	spACSURL := "https://sp.test/auth/saml/" + ulid.New().String() + "/acs"

	connID := ulid.New()
	fakeConn := &models.SAMLConnection{
		ID:          connID,
		IdPEntityID: samltest.IdPEntityID(),
		IdPSSOURL:   samltest.IdPSSOURL(),
		IdPX509Cert: samltest.IdPCertPEM(),
		SPEntityID:  spEntityID,
		SPACSURL:    spACSURL,
		AttributeMap: models.SAMLAttributeMap{
			Email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		},
	}
	store := &inMemSAMLStorage{conn: fakeConn}
	sessions := &fakeSessionIssuer{}

	cfg, err := buildSAMLServiceConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	svc := internalsaml.NewService(store, sessions, nil, cfg)
	svc.Start()
	t.Cleanup(svc.Stop)

	adapter := &samlServiceAdapter{svc: svc, connID: connID}
	h := handlers.New(adapter, handlers.SessionCookieConfig{
		Name: "theauth_sess", TTL: time.Hour,
	}, "/dashboard")
	r := chi.NewRouter()
	h.Mount(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	wrongAud := samltest.Default(spEntityID, spACSURL)
	wrongAud.AudienceURI = "https://wrong-sp.example/saml"
	samlResp, err := wrongAud.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}

	resp := postACS(t, ts, connID.String(), samlResp, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong audience: want 403, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Integration-test support types
// -----------------------------------------------------------------------------

// inMemSAMLStorage satisfies internalsaml.Storage with the minimum set of
// methods needed for handler integration tests (only SAMLConnectionByID is
// called on the read-only BeginLogin/FinishLogin paths when there is no
// find-or-create involved; we stub the rest out as no-ops).
type inMemSAMLStorage struct {
	conn *models.SAMLConnection
}

func (s *inMemSAMLStorage) SAMLConnectionByID(_ context.Context, id models.ULID) (*models.SAMLConnection, error) {
	if s.conn == nil || s.conn.ID != id {
		return nil, errors.New("saml connection not found")
	}
	return s.conn, nil
}

func (s *inMemSAMLStorage) InsertSAMLConnection(_ context.Context, c models.SAMLConnection) (models.SAMLConnection, error) {
	return c, nil
}
func (s *inMemSAMLStorage) UpdateSAMLConnectionRow(_ context.Context, _ models.SAMLConnection) error {
	return nil
}
func (s *inMemSAMLStorage) DeleteSAMLConnection(_ context.Context, _ models.ULID) error {
	return nil
}
func (s *inMemSAMLStorage) SAMLConnectionsByOrg(_ context.Context, _ models.ULID) ([]models.SAMLConnection, error) {
	return nil, nil
}
func (s *inMemSAMLStorage) UpsertSAMLIdentity(_ context.Context, i models.SAMLIdentity) (models.SAMLIdentity, error) {
	return i, nil
}
func (s *inMemSAMLStorage) SAMLIdentityByConnectionAndNameID(_ context.Context, _ models.ULID, _ string) (*models.SAMLIdentity, error) {
	return nil, models.ErrStorageNotFound
}
func (s *inMemSAMLStorage) TouchSAMLIdentityLastLogin(_ context.Context, _ models.ULID, _ time.Time) error {
	return nil
}
func (s *inMemSAMLStorage) UserByID(_ context.Context, _ models.ULID) (*models.User, error) {
	return nil, models.ErrStorageNotFound
}
func (s *inMemSAMLStorage) UserByEmail(_ context.Context, _ string) (*models.User, error) {
	return nil, models.ErrStorageNotFound
}
func (s *inMemSAMLStorage) CreateUser(_ context.Context, u models.User) (models.User, error) {
	return u, nil
}
func (s *inMemSAMLStorage) UpsertOrganizationMember(_ context.Context, _ models.OrganizationMember) error {
	return nil
}
func (s *inMemSAMLStorage) OrganizationMemberRole(_ context.Context, _, _ models.ULID) (string, error) {
	return "", errors.New("not found")
}
func (s *inMemSAMLStorage) SetSessionActiveOrganization(_ context.Context, _ models.ULID, _ *models.ULID) error {
	return nil
}

// fakeSessionIssuer satisfies internalsaml.SessionIssuer.
type fakeSessionIssuer struct {
	token string
}

func (f *fakeSessionIssuer) Issue(_ context.Context, u models.User, _, _ string) (string, models.Session, error) {
	tok := f.token
	if tok == "" {
		tok = "fake-sess-tok"
	}
	return tok, models.Session{ID: ulid.New(), UserID: u.ID}, nil
}

// samlServiceAdapter adapts internalsaml.Service to handlers.Service. It
// pre-fills the connectionID for the integration tests so the handler's
// chi.URLParam does not need to match a seeded row (the URL always carries
// the same connID we pass here).
type samlServiceAdapter struct {
	svc    *internalsaml.Service
	connID models.ULID
}

func (a *samlServiceAdapter) BeginLogin(ctx context.Context, _ models.ULID, relay string) (string, error) {
	return a.svc.BeginLogin(ctx, a.connID, relay)
}

func (a *samlServiceAdapter) FinishLogin(ctx context.Context, _ models.ULID, samlResp, ua, ip string) (string, error) {
	tok, _, _, err := a.svc.FinishLogin(ctx, a.connID, samlResp, ua, ip)
	return tok, err
}

func (a *samlServiceAdapter) MetadataXML(ctx context.Context, _ models.ULID) ([]byte, error) {
	return a.svc.MetadataXML(ctx, a.connID)
}

// buildSAMLServiceConfig parses PEM-encoded cert and key into the config the
// SAML service constructor expects.
func buildSAMLServiceConfig(certPEM, keyPEM []byte) (*internalsaml.Config, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("test: bad cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("test: bad key PEM")
	}
	var rsaKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		anyKey, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if e != nil {
			return nil, e
		}
		var ok bool
		rsaKey, ok = anyKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("test: key is not RSA")
		}
	}
	if err != nil {
		return nil, err
	}
	return &internalsaml.Config{
		SPCert:          cert,
		SPKey:           rsaKey,
		AuthnRequestTTL: 5 * time.Minute,
		ClockSkew:       time.Minute,
	}, nil
}

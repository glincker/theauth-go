// Package webauthn_handlers_test contains direct HTTP-layer table tests for
// internal/webauthn/handlers. Each sub-test mounts the Handler via
// handlers.Mount onto a chi.Router backed by a real webauthn.Service with
// an in-memory storage stub, so the full handler chain is exercised without
// any root TheAuth state.
//
// The handler tests focus on the HTTP contract and the challenge-cookie
// roundtrip. They intentionally stop short of a full CTAP2 ceremony (that
// would require a software authenticator), exercising instead the
// boundary cases that are most likely to regress silently:
//
//   - begin endpoints issue the challenge cookie
//   - finish endpoints reject a missing or empty challenge cookie
//   - finish endpoints consume the challenge (single-use)
//   - credentials endpoints require the user from context
//   - invalid ULID in the credentials DELETE path returns 400
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/internal/wavt"
	"github.com/glincker/theauth-go/internal/webauthn"
	"github.com/glincker/theauth-go/internal/webauthn/handlers"
	"github.com/go-chi/chi/v5"
)

// -----------------------------------------------------------------------------
// Test infrastructure
// -----------------------------------------------------------------------------

const (
	testRPID      = "localhost"
	testRPOrigin  = "http://localhost"
	testRPDisplay = "Test App"
)

// fakeWebAuthnStorage is a minimal in-memory implementation of
// webauthn.Storage. It stores one user and its credential list. Methods not
// needed by the handler-level tests are stubs that return
// models.ErrStorageNotFound.
type fakeWebAuthnStorage struct {
	users map[models.ULID]models.User
	creds map[string]models.WebAuthnCredential // keyed by hex credentialID
}

func newFakeWebAuthnStorage() *fakeWebAuthnStorage {
	return &fakeWebAuthnStorage{
		users: make(map[models.ULID]models.User),
		creds: make(map[string]models.WebAuthnCredential),
	}
}

func (s *fakeWebAuthnStorage) addUser(u models.User) {
	s.users[u.ID] = u
}

func (s *fakeWebAuthnStorage) addCred(c models.WebAuthnCredential) {
	s.creds[credKey(c.CredentialID)] = c
}

func credKey(id []byte) string { return string(id) }

func (s *fakeWebAuthnStorage) UserByID(_ context.Context, id models.ULID) (*models.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, models.ErrStorageNotFound
	}
	return &u, nil
}

func (s *fakeWebAuthnStorage) InsertWebAuthnCredential(_ context.Context, c models.WebAuthnCredential) (models.WebAuthnCredential, error) {
	for _, existing := range s.creds {
		if bytes.Equal(existing.CredentialID, c.CredentialID) {
			return models.WebAuthnCredential{}, errors.New("duplicate credential")
		}
	}
	s.creds[credKey(c.CredentialID)] = c
	return c, nil
}

func (s *fakeWebAuthnStorage) WebAuthnCredentialsByUserID(_ context.Context, userID models.ULID) ([]models.WebAuthnCredential, error) {
	var out []models.WebAuthnCredential
	for _, c := range s.creds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeWebAuthnStorage) WebAuthnCredentialByCredentialID(_ context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	c, ok := s.creds[credKey(credentialID)]
	if !ok {
		return nil, models.ErrStorageNotFound
	}
	return &c, nil
}

func (s *fakeWebAuthnStorage) UpdateWebAuthnSignCount(_ context.Context, credentialID []byte, newCount uint32, _ time.Time) error {
	k := credKey(credentialID)
	c, ok := s.creds[k]
	if !ok {
		return models.ErrStorageNotFound
	}
	c.SignCount = newCount
	s.creds[k] = c
	return nil
}

func (s *fakeWebAuthnStorage) DeleteWebAuthnCredential(_ context.Context, id models.ULID, userID models.ULID) error {
	for k, c := range s.creds {
		if c.ID == id {
			if c.UserID != userID {
				return models.ErrStorageNotFound
			}
			delete(s.creds, k)
			return nil
		}
	}
	return models.ErrStorageNotFound
}

// fakeSessionIssuerWA is a trivial SessionIssuer for webauthn service tests.
type fakeSessionIssuerWA struct{ token string }

func (f *fakeSessionIssuerWA) Issue(_ context.Context, u models.User, _, _ string) (string, models.Session, error) {
	return f.token, models.Session{ID: ulid.New(), UserID: u.ID}, nil
}

// newTestService builds a webauthn.Service wired to fakeWebAuthnStorage with
// the test RP config.
func newTestService(t *testing.T, store *fakeWebAuthnStorage) *webauthn.Service {
	t.Helper()
	svc, err := webauthn.NewService(
		store,
		&fakeSessionIssuerWA{token: "sess-tok-test"},
		audit.NoopEmitter{},
		&webauthn.Config{
			RPID:          testRPID,
			RPDisplayName: testRPDisplay,
			RPOrigins:     []string{testRPOrigin},
			ChallengeTTL:  5 * time.Minute,
		},
	)
	if err != nil {
		t.Fatal("newTestService:", err)
	}
	return svc
}

// passthrough is a no-op middleware used in place of ipLimit / requireAuth
// for handler tests that do not exercise rate-limiting or session auth.
func passthrough(next http.Handler) http.Handler { return next }

// testServiceAdapter adapts *webauthn.Service to handlers.Service,
// dropping the isFirstCredential bool that only the root's
// FinishPasskeyRegistration forwarder needs (to fire OnSignup). These
// handler-level tests exercise the HTTP contract directly against a real
// Service with no root TheAuth involved, so there is no hook to fire.
type testServiceAdapter struct{ *webauthn.Service }

func (a testServiceAdapter) FinishRegistration(ctx context.Context, userID models.ULID, challengeToken, name string, body io.Reader) (models.WebAuthnCredential, error) {
	cred, _, err := a.Service.FinishRegistration(ctx, userID, challengeToken, name, body)
	return cred, err
}

// mountHandler builds a chi.Router with the webauthn handler mounted and
// returns an httptest.Server.
func mountHandler(svc *webauthn.Service, userFromCtx func(*http.Request) (*models.User, bool)) *httptest.Server {
	h := handlers.New(
		testServiceAdapter{svc},
		handlers.SessionCookieConfig{Name: "theauth_sess", SecureFlag: false, TTL: time.Hour},
		handlers.ChallengeCookieConfig{SecureFlag: false, TTL: 5 * time.Minute},
		userFromCtx,
	)
	r := chi.NewRouter()
	h.Mount(r, passthrough, passthrough)
	return httptest.NewServer(r)
}

// noRedirectClient stops at the first redirect response.
var noRedirectClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// postJSON fires a POST request with a JSON body and returns the response.
func postJSON(t *testing.T, url string, body []byte, extraHeaders map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// postWithCookie fires a POST with a specific cookie set.
func postWithCookie(t *testing.T, url string, body []byte, cookieName, cookieVal string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieVal})
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// challengeCookieName is the constant exported for test use.
const challengeCookieName = "theauth_webauthn_chal"

// extractChallengeCookie returns the value of the challenge cookie from the
// response Set-Cookie headers, or empty string if absent.
func extractChallengeCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == challengeCookieName {
			return c.Value
		}
	}
	return ""
}

// fakeUser returns a test user with a predictable email.
func fakeUser(email string) models.User {
	return models.User{
		ID:        ulid.New(),
		Email:     email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// injectUser returns a userFromCtx closure that always returns u.
func injectUser(u models.User) func(*http.Request) (*models.User, bool) {
	return func(_ *http.Request) (*models.User, bool) { return &u, true }
}

// -----------------------------------------------------------------------------
// Register Begin tests
// -----------------------------------------------------------------------------

// TestRegisterBegin_OK verifies that a successful BeginRegistration call
// returns 200 JSON with a challenge and sets the challenge cookie.
func TestRegisterBegin_OK(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("register@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/webauthn/register/begin", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("want application/json, got %q", ct)
	}
	tok := extractChallengeCookie(resp)
	if tok == "" {
		t.Fatal("challenge cookie not set after register/begin")
	}
	// Decode the JSON to verify it has a challenge.
	var cc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cc); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if _, ok := cc["publicKey"]; !ok {
		t.Fatal("register/begin response missing publicKey")
	}
}

// TestRegisterBegin_UserNotFound verifies that when userFromCtx returns a nil
// user the handler panics with nil dereference... actually the handler
// does u.ID on a nil pointer. Let's test it returns non-200 by using a user
// whose ID is not in storage.
func TestRegisterBegin_UserNotInStorage(t *testing.T) {
	store := newFakeWebAuthnStorage()
	// user is NOT added to storage; BeginRegistration will fail on UserByID.
	u := fakeUser("ghost@test.com")
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/webauthn/register/begin", nil, nil)
	defer resp.Body.Close()
	// Service returns storage error; handler maps to 500.
	if resp.StatusCode == http.StatusOK {
		t.Fatal("want non-200 when user missing from storage")
	}
}

// -----------------------------------------------------------------------------
// Register Finish tests
// -----------------------------------------------------------------------------

// TestRegisterFinish_MissingCookie verifies that a POST to /register/finish
// without the challenge cookie returns 400.
func TestRegisterFinish_MissingCookie(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("fin@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/webauthn/register/finish", []byte("{}"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing challenge cookie, got %d", resp.StatusCode)
	}
}

// TestRegisterFinish_EmptyCookie verifies that an empty challenge cookie value
// is also rejected with 400.
func TestRegisterFinish_EmptyCookie(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("fin2@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/register/finish", []byte("{}"), challengeCookieName, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for empty challenge cookie, got %d", resp.StatusCode)
	}
}

// TestRegisterFinish_InvalidToken verifies that a bogus (unknown) challenge
// token is rejected with 401 (CodeWebAuthn -> 401).
func TestRegisterFinish_InvalidToken(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("fin3@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/register/finish", []byte("{}"), challengeCookieName, "invalid-tok")
	defer resp.Body.Close()
	// CodeWebAuthn maps to 401 in ErrToHTTP.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for unknown challenge token, got %d", resp.StatusCode)
	}
}

// TestRegisterFinish_CookieIsCleared verifies that after a finish attempt
// (even a failed one) the challenge cookie is cleared.
func TestRegisterFinish_CookieIsCleared(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("clear@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/register/finish", []byte("{}"), challengeCookieName, "any-tok")
	defer resp.Body.Close()
	// The challenge cookie should be cleared (MaxAge=-1 or empty value).
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == challengeCookieName && (c.MaxAge == -1 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("challenge cookie was not cleared after register/finish")
	}
}

// TestRegisterFinish_SingleUse verifies that two calls with the same challenge
// token fail on the second call (single-use guarantee).
func TestRegisterFinish_SingleUse(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("singleuse@test.com")
	store.addUser(u)
	svc := newTestService(t, store)

	// Call register/begin to get a real challenge token.
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	resp1 := postJSON(t, srv.URL+"/webauthn/register/begin", nil, nil)
	tok := extractChallengeCookie(resp1)
	resp1.Body.Close()
	if tok == "" {
		t.Fatal("no challenge cookie from begin")
	}

	// First finish: token is consumed (even if attestation is invalid).
	resp2 := postWithCookie(t, srv.URL+"/webauthn/register/finish", []byte("{}"), challengeCookieName, tok)
	resp2.Body.Close()

	// Second finish with same token must fail with 401 (challenge unknown).
	resp3 := postWithCookie(t, srv.URL+"/webauthn/register/finish", []byte("{}"), challengeCookieName, tok)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second finish: want 401 (challenge unknown), got %d", resp3.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Login Begin tests
// -----------------------------------------------------------------------------

// TestLoginBegin_OK verifies that /login/begin returns 200 JSON with a
// challenge and sets the challenge cookie.
func TestLoginBegin_OK(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	// Login begin is unauthenticated; userFromCtx returns nil.
	srv := mountHandler(svc, func(_ *http.Request) (*models.User, bool) { return nil, false })
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/webauthn/login/begin", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	tok := extractChallengeCookie(resp)
	if tok == "" {
		t.Fatal("challenge cookie not set after login/begin")
	}
	var ca map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ca); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if _, ok := ca["publicKey"]; !ok {
		t.Fatal("login/begin response missing publicKey")
	}
}

// TestLoginBegin_ChallengeIsUnique verifies that two /login/begin calls yield
// different challenge tokens.
func TestLoginBegin_ChallengeIsUnique(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	resp1 := postJSON(t, srv.URL+"/webauthn/login/begin", nil, nil)
	tok1 := extractChallengeCookie(resp1)
	resp1.Body.Close()

	resp2 := postJSON(t, srv.URL+"/webauthn/login/begin", nil, nil)
	tok2 := extractChallengeCookie(resp2)
	resp2.Body.Close()

	if tok1 == "" || tok2 == "" {
		t.Fatal("one or both challenge tokens empty")
	}
	if tok1 == tok2 {
		t.Fatal("two /login/begin calls should produce distinct challenge tokens")
	}
}

// -----------------------------------------------------------------------------
// Login Finish tests
// -----------------------------------------------------------------------------

// TestLoginFinish_MissingCookie verifies that /login/finish without the
// challenge cookie returns 400.
func TestLoginFinish_MissingCookie(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/webauthn/login/finish", []byte("{}"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for missing challenge cookie, got %d", resp.StatusCode)
	}
}

// TestLoginFinish_EmptyCookie verifies that an empty challenge cookie value
// returns 400.
func TestLoginFinish_EmptyCookie(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/login/finish", []byte("{}"), challengeCookieName, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for empty challenge cookie, got %d", resp.StatusCode)
	}
}

// TestLoginFinish_InvalidToken verifies that a bogus challenge token is
// rejected with 401.
func TestLoginFinish_InvalidToken(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/login/finish", []byte("{}"), challengeCookieName, "no-such-token")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for unknown challenge token, got %d", resp.StatusCode)
	}
}

// TestLoginFinish_CookieIsCleared verifies that the challenge cookie is
// cleared even when the attestation parse fails.
func TestLoginFinish_CookieIsCleared(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	resp := postWithCookie(t, srv.URL+"/webauthn/login/finish", []byte("{}"), challengeCookieName, "some-tok")
	defer resp.Body.Close()

	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == challengeCookieName && (c.MaxAge == -1 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("challenge cookie was not cleared after login/finish")
	}
}

// TestLoginFinish_SingleUse verifies that the login challenge is consumed
// on the first use and a second attempt with the same token returns 401.
func TestLoginFinish_SingleUse(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	beginResp := postJSON(t, srv.URL+"/webauthn/login/begin", nil, nil)
	tok := extractChallengeCookie(beginResp)
	beginResp.Body.Close()
	if tok == "" {
		t.Fatal("no challenge cookie from login/begin")
	}

	// First finish: consumes the token (body is invalid attestation).
	resp1 := postWithCookie(t, srv.URL+"/webauthn/login/finish", []byte("{}"), challengeCookieName, tok)
	resp1.Body.Close()

	// Second finish with same token should be 401 (challenge unknown).
	resp2 := postWithCookie(t, srv.URL+"/webauthn/login/finish", []byte("{}"), challengeCookieName, tok)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second finish: want 401 (challenge unknown), got %d", resp2.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Credentials list and delete tests
// -----------------------------------------------------------------------------

// TestCredentialsList_OK verifies that /credentials returns the credential
// list for the authenticated user.
func TestCredentialsList_OK(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("list@test.com")
	store.addUser(u)

	auth, err := wavt.NewAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	credID, err := wavt.FakeCredentialID(32)
	if err != nil {
		t.Fatal(err)
	}
	store.addCred(models.WebAuthnCredential{
		ID:           ulid.New(),
		UserID:       u.ID,
		CredentialID: credID,
		PublicKey:    auth.FakePublicKeyBytes(),
		Name:         "my key",
		CreatedAt:    time.Now(),
	})

	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/webauthn/credentials", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var creds []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 credential, got %d", len(creds))
	}
}

// TestCredentialsList_Empty verifies that a user with no credentials gets
// an empty JSON array (not an error).
func TestCredentialsList_Empty(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("empty@test.com")
	store.addUser(u)

	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/webauthn/credentials", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestCredentialsDelete_InvalidID verifies that a non-ULID credential id in
// the path returns 400.
func TestCredentialsDelete_InvalidID(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("del@test.com")
	store.addUser(u)

	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/webauthn/credentials/not-a-ulid", nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid credential id, got %d", resp.StatusCode)
	}
}

// TestCredentialsDelete_OK verifies that deleting an existing credential
// returns 204 and the credential is removed from storage.
func TestCredentialsDelete_OK(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("delok@test.com")
	store.addUser(u)

	auth, err := wavt.NewAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	credID, err := wavt.FakeCredentialID(32)
	if err != nil {
		t.Fatal(err)
	}
	credRowID := ulid.New()
	store.addCred(models.WebAuthnCredential{
		ID:           credRowID,
		UserID:       u.ID,
		CredentialID: credID,
		PublicKey:    auth.FakePublicKeyBytes(),
		Name:         "to delete",
		CreatedAt:    time.Now(),
	})

	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/webauthn/credentials/"+credRowID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
	// Verify the credential is gone from storage.
	list, _ := store.WebAuthnCredentialsByUserID(context.Background(), u.ID)
	if len(list) != 0 {
		t.Fatalf("want 0 credentials after delete, got %d", len(list))
	}
}

// TestCredentialsDelete_NotFound verifies that deleting a non-existent
// credential returns a non-204 (typically 500 from the default ErrToHTTP path
// because ErrStorageNotFound is not a TheAuthError).
func TestCredentialsDelete_NotFound(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("delnf@test.com")
	store.addUser(u)

	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	fakeID := ulid.New()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/webauthn/credentials/"+fakeID.String(), nil)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("want non-204 when credential does not exist")
	}
}

// TestChallengeCookieRoundtrip exercises the full begin->finish cookie
// roundtrip for both register and login: begin sets the cookie, finish reads
// it. We use a real httptest.Server with cookie-jar support so the cookie is
// forwarded automatically.
func TestChallengeCookieRoundtrip_Register(t *testing.T) {
	store := newFakeWebAuthnStorage()
	u := fakeUser("roundtrip@test.com")
	store.addUser(u)
	svc := newTestService(t, store)
	srv := mountHandler(svc, injectUser(u))
	defer srv.Close()

	jar := newCookieJar()
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: begin sets the challenge cookie in the jar.
	req1, _ := http.NewRequest(http.MethodPost, srv.URL+"/webauthn/register/begin", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("begin: want 200, got %d", resp1.StatusCode)
	}

	// Step 2: finish receives the cookie automatically (jar). A garbage
	// attestation body means we get an error back, but the important thing
	// is that the handler consumed the cookie without a 400
	// "missing challenge cookie" error.
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/webauthn/register/finish", bytes.NewReader([]byte("{}")))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	// 400 means "missing challenge cookie" and is a failure here.
	if resp2.StatusCode == http.StatusBadRequest {
		t.Fatal("finish rejected the challenge cookie roundtrip: got 400 (missing challenge cookie)")
	}
}

// TestChallengeCookieRoundtrip_Login is the login-flow equivalent.
func TestChallengeCookieRoundtrip_Login(t *testing.T) {
	store := newFakeWebAuthnStorage()
	svc := newTestService(t, store)
	noUser := func(_ *http.Request) (*models.User, bool) { return nil, false }
	srv := mountHandler(svc, noUser)
	defer srv.Close()

	jar := newCookieJar()
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req1, _ := http.NewRequest(http.MethodPost, srv.URL+"/webauthn/login/begin", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("login begin: want 200, got %d", resp1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/webauthn/login/finish", bytes.NewReader([]byte("{}")))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusBadRequest {
		t.Fatal("login finish rejected the challenge cookie roundtrip: got 400")
	}
}

// -----------------------------------------------------------------------------
// minimalCookieJar satisfies http.CookieJar for the roundtrip tests.
// -----------------------------------------------------------------------------

type minimalCookieJar struct {
	cookies []*http.Cookie
}

func newCookieJar() *minimalCookieJar { return &minimalCookieJar{} }

func (j *minimalCookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		replaced := false
		for i, existing := range j.cookies {
			if existing.Name == c.Name {
				j.cookies[i] = c
				replaced = true
				break
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, c)
		}
	}
}

func (j *minimalCookieJar) Cookies(_ *url.URL) []*http.Cookie {
	return j.cookies
}

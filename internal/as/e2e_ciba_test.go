package as_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// e2e_ciba_test.go: end-to-end CIBA (RFC 9509) tests against the real AS +
// real in-memory storage + real httptest server.

// testAuthDevice is a test AuthenticationDevice that records the last notification.
type testAuthDevice struct {
	last theauth.CIBANotification
	err  error // if non-nil, Notify returns this error
}

func (d *testAuthDevice) Notify(_ context.Context, n theauth.CIBANotification) error {
	d.last = n
	return d.err
}

// newCIBAASInstance creates a TheAuth instance with CIBA enabled.
func newCIBAASInstance(t *testing.T, device theauth.AuthenticationDevice) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	a, store := newASInstance(t, func(cfg *theauth.AuthorizationServerConfig) {
		cfg.RegistrationTokens = []string{"ciba-test-token"}
		cfg.CIBA = &theauth.CIBAConfig{
			AuthenticationDevice: device,
			DefaultExpiry:        30 * time.Second,
			DefaultInterval:      5 * time.Second,
			MaxRequestedExpiry:   60 * time.Second,
			MinPollInterval:      2 * time.Second,
		}
	})
	return a, store
}

// registerCIBAClient registers a confidential OAuth client for use in CIBA tests.
func registerCIBAClient(t *testing.T, srv *httptest.Server) theauth.RegisteredClient {
	t.Helper()
	body := `{
		"client_name": "ciba-test",
		"grant_types": ["urn:openid:params:grant-type:ciba","refresh_token"],
		"token_endpoint_auth_method": "client_secret_basic"
	}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ciba-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d", resp.StatusCode)
	}
	var rc theauth.RegisteredClient
	if err := json.NewDecoder(resp.Body).Decode(&rc); err != nil {
		t.Fatalf("decode registered client: %v", err)
	}
	return rc
}

// postBCAuthorize calls POST /oauth/bc-authorize and returns the raw response.
func postBCAuthorize(t *testing.T, srv *httptest.Server, client theauth.RegisteredClient, params map[string]string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("client_id", client.ClientID)
	form.Set("client_secret", client.ClientSecret)
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth/bc-authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("bc-authorize request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bc-authorize: %v", err)
	}
	return resp
}

// pollCIBAToken calls POST /oauth/token with the CIBA grant type.
func pollCIBAToken(t *testing.T, srv *httptest.Server, client theauth.RegisteredClient, authReqID string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":  []string{theauth.GrantTypeCIBA},
		"auth_req_id": []string{authReqID},
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("poll request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, client.ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	return resp
}

// oauthErrCode decodes the "error" field from an OAuth JSON error body.
func oauthErrCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return body.Error
}

// TestCIBAPollHappyPath verifies the full Poll-mode flow:
// bc-authorize -> pending poll -> operator approval -> token poll returns tokens.
func TestCIBAPollHappyPath(t *testing.T) {
	dev := &testAuthDevice{}
	a, _ := newCIBAASInstance(t, dev)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	// Register the AS anonymously for this test (simple path).
	client := registerCIBAClient(t, srv)

	// POST /oauth/bc-authorize.
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope":           "files.read",
		"login_hint":      "alice@example.com",
		"binding_message": "Approve CIBA test",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize: status %d", resp.StatusCode)
	}
	var bcResp struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int    `json:"expires_in"`
		Interval  int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bcResp); err != nil {
		t.Fatalf("decode bc-authorize response: %v", err)
	}
	if bcResp.AuthReqID == "" {
		t.Fatal("auth_req_id is empty")
	}
	if bcResp.ExpiresIn <= 0 {
		t.Fatalf("expires_in %d <= 0", bcResp.ExpiresIn)
	}
	if bcResp.Interval <= 0 {
		t.Fatalf("interval %d <= 0", bcResp.Interval)
	}

	// Verify the AuthenticationDevice received the notification.
	if dev.last.AuthReqID != bcResp.AuthReqID {
		t.Fatalf("device AuthReqID=%q, want %q", dev.last.AuthReqID, bcResp.AuthReqID)
	}
	if dev.last.BindingMessage != "Approve CIBA test" {
		t.Fatalf("binding_message=%q", dev.last.BindingMessage)
	}

	// First poll: expect authorization_pending.
	pollResp := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	if pollResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending poll: status %d", pollResp.StatusCode)
	}
	if code := oauthErrCode(t, pollResp); code != "authorization_pending" {
		t.Fatalf("pending poll error code=%q", code)
	}

	// Operator approves via ApproveBackchannelAuth.
	userID := ulid.New()
	if err := a.ApproveBackchannelAuth(context.Background(), bcResp.AuthReqID, userID); err != nil {
		t.Fatalf("ApproveBackchannelAuth: %v", err)
	}

	// Wait just past MinPollInterval to avoid slow_down.
	time.Sleep(3 * time.Second)

	// Next poll: should return tokens.
	pollResp2 := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	defer func() { _ = pollResp2.Body.Close() }()
	if pollResp2.StatusCode != http.StatusOK {
		t.Fatalf("approved poll: status %d", pollResp2.StatusCode)
	}
	var tokResp theauth.TokenResponse
	if err := json.NewDecoder(pollResp2.Body).Decode(&tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokResp.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
}

// TestCIBASlowDown verifies that polling faster than MinPollInterval returns
// slow_down on the second immediate call.
func TestCIBASlowDown(t *testing.T) {
	dev := &testAuthDevice{}
	_, _ = newCIBAASInstance(t, dev) // create store via AS but use HTTP directly
	a, _ := newCIBAASInstance(t, dev)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	client := registerCIBAClient(t, srv)
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope":      "files.read",
		"login_hint": "bob@example.com",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize: status %d", resp.StatusCode)
	}
	var bcResp struct {
		AuthReqID string `json:"auth_req_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&bcResp)

	// First poll: pending (records LastPollAt).
	r1 := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	_ = r1.Body.Close()

	// Immediate second poll (no sleep): should be slow_down.
	r2 := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("slow_down: status %d", r2.StatusCode)
	}
	if code := oauthErrCode(t, r2); code != "slow_down" {
		t.Fatalf("expected slow_down, got %q", code)
	}
}

// TestCIBAAccessDenied verifies that DenyBackchannelAuth makes the next poll
// return access_denied.
func TestCIBAAccessDenied(t *testing.T) {
	dev := &testAuthDevice{}
	a, _ := newCIBAASInstance(t, dev)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	client := registerCIBAClient(t, srv)
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope":      "files.read",
		"login_hint": "carol@example.com",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize: status %d", resp.StatusCode)
	}
	var bcResp struct {
		AuthReqID string `json:"auth_req_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&bcResp)

	// Operator denies.
	userID := ulid.New()
	if err := a.DenyBackchannelAuth(context.Background(), bcResp.AuthReqID, userID); err != nil {
		t.Fatalf("DenyBackchannelAuth: %v", err)
	}

	// Wait past MinPollInterval.
	time.Sleep(3 * time.Second)

	pollResp := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	if pollResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("access_denied: status %d", pollResp.StatusCode)
	}
	if code := oauthErrCode(t, pollResp); code != "access_denied" {
		t.Fatalf("expected access_denied, got %q", code)
	}
}

// TestCIBAExpiredToken verifies that polling after ExpiresAt returns expired_token.
func TestCIBAExpiredToken(t *testing.T) {
	dev := &testAuthDevice{}
	// Use a very short expiry (1 second) for this test.
	a, store := newASInstance(t, func(cfg *theauth.AuthorizationServerConfig) {
		cfg.RegistrationTokens = []string{"ciba-test-token"}
		cfg.CIBA = &theauth.CIBAConfig{
			AuthenticationDevice: dev,
			DefaultExpiry:        1 * time.Second,
			DefaultInterval:      1 * time.Second,
			MaxRequestedExpiry:   5 * time.Second,
			MinPollInterval:      0,
		}
	})
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	_ = store

	client := registerCIBAClient(t, srv)
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope":      "files.read",
		"login_hint": "dave@example.com",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize: status %d", resp.StatusCode)
	}
	var bcResp struct {
		AuthReqID string `json:"auth_req_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&bcResp)

	// Wait for expiry.
	time.Sleep(2 * time.Second)

	pollResp := pollCIBAToken(t, srv, client, bcResp.AuthReqID)
	if pollResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired_token: status %d", pollResp.StatusCode)
	}
	if code := oauthErrCode(t, pollResp); code != "expired_token" {
		t.Fatalf("expected expired_token, got %q", code)
	}
}

// TestCIBARequiresLoginHint verifies that omitting all hint parameters returns
// invalid_request.
func TestCIBARequiresLoginHint(t *testing.T) {
	dev := &testAuthDevice{}
	a, _ := newCIBAASInstance(t, dev)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	client := registerCIBAClient(t, srv)

	// No hint parameters at all.
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope": "files.read",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no hint: status %d (want 400)", resp.StatusCode)
	}
	if code := oauthErrCode(t, resp); code != "invalid_request" {
		t.Fatalf("no hint error=%q (want invalid_request)", code)
	}

	// Multiple hints: should also be invalid_request.
	resp2 := postBCAuthorize(t, srv, client, map[string]string{
		"scope":            "files.read",
		"login_hint":       "alice@example.com",
		"login_hint_token": "tok123",
	})
	if resp2.StatusCode != http.StatusBadRequest {
		_ = resp2.Body.Close()
		t.Fatalf("multi hint: status %d (want 400)", resp2.StatusCode)
	}
	if code := oauthErrCode(t, resp2); code != "invalid_request" {
		t.Fatalf("multi hint error=%q (want invalid_request)", code)
	}
}

// TestCIBABindingMessageInNotification verifies that the AuthenticationDevice
// receives the binding_message supplied in the bc-authorize request.
func TestCIBABindingMessageInNotification(t *testing.T) {
	dev := &testAuthDevice{}
	a, _ := newCIBAASInstance(t, dev)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	client := registerCIBAClient(t, srv)
	const wantMsg = "Confirm $500 transfer to Alice"
	resp := postBCAuthorize(t, srv, client, map[string]string{
		"scope":           "files.read",
		"login_hint":      "alice@example.com",
		"binding_message": wantMsg,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize: status %d", resp.StatusCode)
	}
	if dev.last.BindingMessage != wantMsg {
		t.Fatalf("BindingMessage=%q, want %q", dev.last.BindingMessage, wantMsg)
	}
}

// TestCIBAStorageMissing verifies that when the storage does not implement
// CIBAStorage, bc-authorize returns 404 and the AS metadata does not advertise
// the backchannel endpoint.
func TestCIBAStorageMissing(t *testing.T) {
	// Create an AS whose storage is a minimal wrapper that does NOT implement
	// CIBAStorage.
	noopStore := &noCIBAStore{inner: memory.New()}
	dev := &testAuthDevice{}

	import_key := make([]byte, 32)
	a, err := theauth.New(theauth.Config{
		Storage:       noopStore,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: import_key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:                     "https://auth.example.com",
			Resources:                  []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
			DisableRotation:            true,
			AllowAnonymousRegistration: true,
			CIBA: &theauth.CIBAConfig{
				AuthenticationDevice: dev,
			},
		},
	})
	// New succeeds because CIBA config is valid; CIBA is disabled at runtime.
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)

	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	// /oauth/bc-authorize should be 404 (route not mounted).
	resp, err := http.Post(srv.URL+"/oauth/bc-authorize", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("bc-authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bc-authorize: status %d (want 404)", resp.StatusCode)
	}

	// AS metadata should not include backchannel_authentication_endpoint.
	metaResp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	defer func() { _ = metaResp.Body.Close() }()
	var meta map[string]interface{}
	if err := json.NewDecoder(metaResp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if _, ok := meta["backchannel_authentication_endpoint"]; ok {
		t.Fatal("metadata should not contain backchannel_authentication_endpoint when CIBAStorage is absent")
	}
}

// noCIBAStore wraps a memory.Store but does NOT implement CIBAStorage, so
// the CIBA feature is auto-disabled even when CIBAConfig is set.
type noCIBAStore struct {
	inner *memory.Store
}

// Delegate all Storage methods to inner. We embed the full interface by
// promoting the inner store's methods via embedding, then suppress CIBAStorage
// by NOT adding the CIBA methods.
func (s *noCIBAStore) CreateUser(ctx context.Context, u theauth.User) (theauth.User, error) {
	return s.inner.CreateUser(ctx, u)
}
func (s *noCIBAStore) UserByEmail(ctx context.Context, email string) (*theauth.User, error) {
	return s.inner.UserByEmail(ctx, email)
}
func (s *noCIBAStore) UserByID(ctx context.Context, id theauth.ULID) (*theauth.User, error) {
	return s.inner.UserByID(ctx, id)
}
func (s *noCIBAStore) MarkEmailVerified(ctx context.Context, userID theauth.ULID) error {
	return s.inner.MarkEmailVerified(ctx, userID)
}
func (s *noCIBAStore) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.inner.CreateSession(ctx, sess)
}
func (s *noCIBAStore) SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error) {
	return s.inner.SessionByTokenHash(ctx, hash)
}
func (s *noCIBAStore) RevokeSession(ctx context.Context, id theauth.ULID) error {
	return s.inner.RevokeSession(ctx, id)
}
func (s *noCIBAStore) RevokeUserSessions(ctx context.Context, userID theauth.ULID) error {
	return s.inner.RevokeUserSessions(ctx, userID)
}
func (s *noCIBAStore) CreateMagicLink(ctx context.Context, ml theauth.MagicLink) error {
	return s.inner.CreateMagicLink(ctx, ml)
}
func (s *noCIBAStore) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*theauth.MagicLink, error) {
	return s.inner.ConsumeMagicLink(ctx, tokenHash)
}
func (s *noCIBAStore) SetUserPassword(ctx context.Context, userID theauth.ULID, passwordHash string) error {
	return s.inner.SetUserPassword(ctx, userID, passwordHash)
}
func (s *noCIBAStore) UserByEmailWithPassword(ctx context.Context, email string) (*theauth.User, string, error) {
	return s.inner.UserByEmailWithPassword(ctx, email)
}
func (s *noCIBAStore) CreatePasswordResetToken(ctx context.Context, t theauth.PasswordResetToken) error {
	return s.inner.CreatePasswordResetToken(ctx, t)
}
func (s *noCIBAStore) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*theauth.PasswordResetToken, error) {
	return s.inner.ConsumePasswordResetToken(ctx, tokenHash)
}
func (s *noCIBAStore) UpsertOAuthAccount(ctx context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	return s.inner.UpsertOAuthAccount(ctx, a)
}
func (s *noCIBAStore) OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	return s.inner.OAuthAccountByProviderUserID(ctx, provider, providerUserID)
}
func (s *noCIBAStore) OAuthAccountsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.OAuthAccount, error) {
	return s.inner.OAuthAccountsByUserID(ctx, userID)
}
func (s *noCIBAStore) MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID theauth.ULID) error {
	return s.inner.MoveOAuthAccount(ctx, provider, providerUserID, newUserID)
}
func (s *noCIBAStore) DeleteOAuthAccountByProvider(ctx context.Context, userID theauth.ULID, provider string) error {
	return s.inner.DeleteOAuthAccountByProvider(ctx, userID, provider)
}
func (s *noCIBAStore) UserPasswordHashByID(ctx context.Context, userID theauth.ULID) (string, error) {
	return s.inner.UserPasswordHashByID(ctx, userID)
}
func (s *noCIBAStore) MovePasswordHash(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	return s.inner.MovePasswordHash(ctx, primaryID, secondaryID)
}
func (s *noCIBAStore) MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	return s.inner.MoveWebAuthnCredentials(ctx, primaryID, secondaryID)
}
func (s *noCIBAStore) MoveTOTPSecret(ctx context.Context, primaryID, secondaryID theauth.ULID) error {
	return s.inner.MoveTOTPSecret(ctx, primaryID, secondaryID)
}
func (s *noCIBAStore) CreateSessionWithAuthLevel(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	return s.inner.CreateSessionWithAuthLevel(ctx, sess)
}
func (s *noCIBAStore) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	return s.inner.UpdateSessionAuthLevel(ctx, id, level)
}
func (s *noCIBAStore) InsertWebAuthnCredential(ctx context.Context, c theauth.WebAuthnCredential) (theauth.WebAuthnCredential, error) {
	return s.inner.InsertWebAuthnCredential(ctx, c)
}
func (s *noCIBAStore) WebAuthnCredentialsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.WebAuthnCredential, error) {
	return s.inner.WebAuthnCredentialsByUserID(ctx, userID)
}
func (s *noCIBAStore) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*theauth.WebAuthnCredential, error) {
	return s.inner.WebAuthnCredentialByCredentialID(ctx, credentialID)
}
func (s *noCIBAStore) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error {
	return s.inner.UpdateWebAuthnSignCount(ctx, credentialID, newCount, usedAt)
}
func (s *noCIBAStore) DeleteWebAuthnCredential(ctx context.Context, id theauth.ULID, userID theauth.ULID) error {
	return s.inner.DeleteWebAuthnCredential(ctx, id, userID)
}
func (s *noCIBAStore) UpsertPendingTOTPSecret(ctx context.Context, sec theauth.TOTPSecret) error {
	return s.inner.UpsertPendingTOTPSecret(ctx, sec)
}
func (s *noCIBAStore) ConfirmTOTPSecret(ctx context.Context, userID theauth.ULID, at time.Time) error {
	return s.inner.ConfirmTOTPSecret(ctx, userID, at)
}
func (s *noCIBAStore) TOTPSecretByUserID(ctx context.Context, userID theauth.ULID) (*theauth.TOTPSecret, error) {
	return s.inner.TOTPSecretByUserID(ctx, userID)
}
func (s *noCIBAStore) DeleteTOTPSecret(ctx context.Context, userID theauth.ULID) error {
	return s.inner.DeleteTOTPSecret(ctx, userID)
}
func (s *noCIBAStore) InsertRecoveryCodes(ctx context.Context, codes []theauth.RecoveryCode) error {
	return s.inner.InsertRecoveryCodes(ctx, codes)
}
func (s *noCIBAStore) ConsumeRecoveryCode(ctx context.Context, userID theauth.ULID, code string, at time.Time) error {
	return s.inner.ConsumeRecoveryCode(ctx, userID, code, at)
}
func (s *noCIBAStore) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	return s.inner.InsertAuditEvents(ctx, events)
}
func (s *noCIBAStore) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	return s.inner.QueryAuditEvents(ctx, q)
}

// OAuthServerStorage methods forwarded to inner.
func (s *noCIBAStore) InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	return s.inner.InsertOAuthClient(ctx, c)
}
func (s *noCIBAStore) OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error) {
	return s.inner.OAuthClientByClientID(ctx, clientID)
}
func (s *noCIBAStore) UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	return s.inner.UpdateOAuthClient(ctx, c)
}
func (s *noCIBAStore) DeleteOAuthClient(ctx context.Context, clientID string) error {
	return s.inner.DeleteOAuthClient(ctx, clientID)
}
func (s *noCIBAStore) InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error {
	return s.inner.InsertAuthorizationCode(ctx, c)
}
func (s *noCIBAStore) ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error) {
	return s.inner.ConsumeAuthorizationCode(ctx, code)
}
func (s *noCIBAStore) InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error {
	return s.inner.InsertRefreshToken(ctx, t)
}
func (s *noCIBAStore) RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error) {
	return s.inner.RefreshTokenByHash(ctx, hash)
}
func (s *noCIBAStore) RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error {
	return s.inner.RevokeRefreshToken(ctx, hash, reason)
}
func (s *noCIBAStore) RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error {
	return s.inner.RevokeRefreshTokenFamily(ctx, familyID, reason)
}
func (s *noCIBAStore) InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error {
	return s.inner.InsertJWKSKey(ctx, k)
}
func (s *noCIBAStore) JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error) {
	return s.inner.JWKSKeyByKID(ctx, kid)
}
func (s *noCIBAStore) JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error) {
	return s.inner.JWKSKeysAll(ctx)
}
func (s *noCIBAStore) UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error {
	return s.inner.UpdateJWKSKeyState(ctx, kid, state, at)
}
func (s *noCIBAStore) InsertAgent(ctx context.Context, agent theauth.Agent) (theauth.Agent, error) {
	return s.inner.InsertAgent(ctx, agent)
}
func (s *noCIBAStore) AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error) {
	return s.inner.AgentByID(ctx, id)
}
func (s *noCIBAStore) AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error) {
	return s.inner.AgentByClientID(ctx, clientID)
}
func (s *noCIBAStore) AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error) {
	return s.inner.AgentsByOwner(ctx, owner)
}
func (s *noCIBAStore) UpdateAgentStatus(ctx context.Context, id theauth.ULID, status string, at time.Time) error {
	return s.inner.UpdateAgentStatus(ctx, id, status, at)
}
func (s *noCIBAStore) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.UpdateAgentLastActive(ctx, id, at)
}
func (s *noCIBAStore) InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error {
	return s.inner.InsertAgentCredential(ctx, c)
}
func (s *noCIBAStore) AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error) {
	return s.inner.AgentCredentialsByAgentID(ctx, agentID)
}
func (s *noCIBAStore) RevokeAgentCredential(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.RevokeAgentCredential(ctx, id, at)
}
func (s *noCIBAStore) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.UpdateAgentCredentialLastUsed(ctx, id, at)
}
func (s *noCIBAStore) InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	return s.inner.InsertDelegationGrant(ctx, g)
}
func (s *noCIBAStore) DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error) {
	return s.inner.DelegationGrantByID(ctx, id)
}
func (s *noCIBAStore) DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error) {
	return s.inner.DelegationGrantByUserAgentResource(ctx, userID, agentID, resource)
}
func (s *noCIBAStore) DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.inner.DelegationGrantsByUserID(ctx, userID)
}
func (s *noCIBAStore) DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.inner.DelegationGrantsByAgentID(ctx, agentID)
}
func (s *noCIBAStore) RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error {
	return s.inner.RevokeDelegationGrant(ctx, id, at, reason)
}

// Organization / SAML / SCIM / RBAC methods (all no-ops for this test).
func (s *noCIBAStore) InsertOrganization(ctx context.Context, o theauth.Organization) (theauth.Organization, error) {
	return s.inner.InsertOrganization(ctx, o)
}
func (s *noCIBAStore) OrganizationByID(ctx context.Context, id theauth.ULID) (*theauth.Organization, error) {
	return s.inner.OrganizationByID(ctx, id)
}
func (s *noCIBAStore) OrganizationBySlug(ctx context.Context, slug string) (*theauth.Organization, error) {
	return s.inner.OrganizationBySlug(ctx, slug)
}
func (s *noCIBAStore) UpdateOrganization(ctx context.Context, o theauth.Organization) error {
	return s.inner.UpdateOrganization(ctx, o)
}
func (s *noCIBAStore) DeleteOrganization(ctx context.Context, id theauth.ULID) error {
	return s.inner.DeleteOrganization(ctx, id)
}
func (s *noCIBAStore) UpsertOrganizationMember(ctx context.Context, m theauth.OrganizationMember) error {
	return s.inner.UpsertOrganizationMember(ctx, m)
}
func (s *noCIBAStore) DeleteOrganizationMember(ctx context.Context, orgID, userID theauth.ULID) error {
	return s.inner.DeleteOrganizationMember(ctx, orgID, userID)
}
func (s *noCIBAStore) OrganizationMembersByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.OrganizationMember, error) {
	return s.inner.OrganizationMembersByOrg(ctx, orgID)
}
func (s *noCIBAStore) OrganizationsByUser(ctx context.Context, userID theauth.ULID) ([]theauth.Organization, error) {
	return s.inner.OrganizationsByUser(ctx, userID)
}
func (s *noCIBAStore) OrganizationMemberRole(ctx context.Context, orgID, userID theauth.ULID) (string, error) {
	return s.inner.OrganizationMemberRole(ctx, orgID, userID)
}
func (s *noCIBAStore) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	return s.inner.SetSessionActiveOrganization(ctx, sessionID, orgID)
}
func (s *noCIBAStore) InsertSAMLConnection(ctx context.Context, c theauth.SAMLConnection) (theauth.SAMLConnection, error) {
	return s.inner.InsertSAMLConnection(ctx, c)
}
func (s *noCIBAStore) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	return s.inner.UpdateSAMLConnectionRow(ctx, c)
}
func (s *noCIBAStore) DeleteSAMLConnection(ctx context.Context, id theauth.ULID) error {
	return s.inner.DeleteSAMLConnection(ctx, id)
}
func (s *noCIBAStore) SAMLConnectionByID(ctx context.Context, id theauth.ULID) (*theauth.SAMLConnection, error) {
	return s.inner.SAMLConnectionByID(ctx, id)
}
func (s *noCIBAStore) SAMLConnectionsByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SAMLConnection, error) {
	return s.inner.SAMLConnectionsByOrg(ctx, orgID)
}
func (s *noCIBAStore) UpsertSAMLIdentity(ctx context.Context, i theauth.SAMLIdentity) (theauth.SAMLIdentity, error) {
	return s.inner.UpsertSAMLIdentity(ctx, i)
}
func (s *noCIBAStore) SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID theauth.ULID, nameID string) (*theauth.SAMLIdentity, error) {
	return s.inner.SAMLIdentityByConnectionAndNameID(ctx, connectionID, nameID)
}
func (s *noCIBAStore) TouchSAMLIdentityLastLogin(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.TouchSAMLIdentityLastLogin(ctx, id, at)
}
func (s *noCIBAStore) InsertSCIMToken(ctx context.Context, t theauth.SCIMToken) (theauth.SCIMToken, error) {
	return s.inner.InsertSCIMToken(ctx, t)
}
func (s *noCIBAStore) SCIMTokenByHash(ctx context.Context, hash []byte) (*theauth.SCIMToken, error) {
	return s.inner.SCIMTokenByHash(ctx, hash)
}
func (s *noCIBAStore) SCIMTokensByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SCIMToken, error) {
	return s.inner.SCIMTokensByOrg(ctx, orgID)
}
func (s *noCIBAStore) RevokeSCIMTokenByID(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.RevokeSCIMTokenByID(ctx, id, at)
}
func (s *noCIBAStore) TouchSCIMTokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	return s.inner.TouchSCIMTokenLastUsed(ctx, id, at)
}
func (s *noCIBAStore) ListUsersByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMUserFilter) ([]theauth.User, int, error) {
	return s.inner.ListUsersByOrganization(ctx, orgID, offset, limit, filter)
}
func (s *noCIBAStore) ListGroupsByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMGroupFilter) ([]theauth.Group, int, error) {
	return s.inner.ListGroupsByOrganization(ctx, orgID, offset, limit, filter)
}
func (s *noCIBAStore) UserByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.User, error) {
	return s.inner.UserByExternalIDInOrg(ctx, orgID, externalID)
}
func (s *noCIBAStore) UpdateUserSCIM(ctx context.Context, u theauth.User) error {
	return s.inner.UpdateUserSCIM(ctx, u)
}
func (s *noCIBAStore) InsertGroup(ctx context.Context, g theauth.Group) (theauth.Group, error) {
	return s.inner.InsertGroup(ctx, g)
}
func (s *noCIBAStore) GroupByID(ctx context.Context, id theauth.ULID) (*theauth.Group, error) {
	return s.inner.GroupByID(ctx, id)
}
func (s *noCIBAStore) GroupByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.Group, error) {
	return s.inner.GroupByExternalIDInOrg(ctx, orgID, externalID)
}
func (s *noCIBAStore) UpdateGroup(ctx context.Context, g theauth.Group) error {
	return s.inner.UpdateGroup(ctx, g)
}
func (s *noCIBAStore) DeleteGroup(ctx context.Context, id theauth.ULID) error {
	return s.inner.DeleteGroup(ctx, id)
}
func (s *noCIBAStore) SetGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inner.SetGroupMembers(ctx, groupID, userIDs)
}
func (s *noCIBAStore) AddGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inner.AddGroupMembers(ctx, groupID, userIDs)
}
func (s *noCIBAStore) RemoveGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inner.RemoveGroupMembers(ctx, groupID, userIDs)
}
func (s *noCIBAStore) GroupMembers(ctx context.Context, groupID theauth.ULID) ([]theauth.ULID, error) {
	return s.inner.GroupMembers(ctx, groupID)
}
func (s *noCIBAStore) InsertPermission(ctx context.Context, p theauth.Permission) (theauth.Permission, error) {
	return s.inner.InsertPermission(ctx, p)
}
func (s *noCIBAStore) PermissionByName(ctx context.Context, name string) (*theauth.Permission, error) {
	return s.inner.PermissionByName(ctx, name)
}
func (s *noCIBAStore) ListPermissions(ctx context.Context) ([]theauth.Permission, error) {
	return s.inner.ListPermissions(ctx)
}
func (s *noCIBAStore) InsertRole(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	return s.inner.InsertRole(ctx, r)
}
func (s *noCIBAStore) UpdateRoleRow(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	return s.inner.UpdateRoleRow(ctx, r)
}
func (s *noCIBAStore) DeleteRole(ctx context.Context, id theauth.ULID) error {
	return s.inner.DeleteRole(ctx, id)
}
func (s *noCIBAStore) RoleByID(ctx context.Context, id theauth.ULID) (*theauth.Role, error) {
	return s.inner.RoleByID(ctx, id)
}
func (s *noCIBAStore) RoleByOrgAndName(ctx context.Context, orgID *theauth.ULID, name string) (*theauth.Role, error) {
	return s.inner.RoleByOrgAndName(ctx, orgID, name)
}
func (s *noCIBAStore) RolesByOrganization(ctx context.Context, orgID *theauth.ULID) ([]theauth.Role, error) {
	return s.inner.RolesByOrganization(ctx, orgID)
}
func (s *noCIBAStore) SetRolePermissions(ctx context.Context, roleID theauth.ULID, permissionIDs []theauth.ULID) error {
	return s.inner.SetRolePermissions(ctx, roleID, permissionIDs)
}
func (s *noCIBAStore) PermissionsByRole(ctx context.Context, roleID theauth.ULID) ([]string, error) {
	return s.inner.PermissionsByRole(ctx, roleID)
}
func (s *noCIBAStore) GrantUserRole(ctx context.Context, ur theauth.UserRole) error {
	return s.inner.GrantUserRole(ctx, ur)
}
func (s *noCIBAStore) RevokeUserRole(ctx context.Context, userID, roleID theauth.ULID) error {
	return s.inner.RevokeUserRole(ctx, userID, roleID)
}
func (s *noCIBAStore) RolesForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]theauth.Role, error) {
	return s.inner.RolesForUser(ctx, userID, orgID)
}
func (s *noCIBAStore) PermissionsForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]string, error) {
	return s.inner.PermissionsForUser(ctx, userID, orgID)
}
func (s *noCIBAStore) CountUsersWithPermissionInOrg(ctx context.Context, orgID theauth.ULID, perm string) (int, error) {
	return s.inner.CountUsersWithPermissionInOrg(ctx, orgID, perm)
}

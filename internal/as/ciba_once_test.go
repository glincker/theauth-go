package as_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// approvedCIBA starts a CIBA flow with no poll throttling and approves it.
func approvedCIBA(t *testing.T, expiry time.Duration) (srv *httptest.Server, client theauth.RegisteredClient, authReqID string, a *theauth.TheAuth) {
	t.Helper()
	a, _ = newASInstance(t, func(cfg *theauth.AuthorizationServerConfig) {
		cfg.RegistrationTokens = []string{"ciba-test-token"}
		cfg.CIBA = &theauth.CIBAConfig{
			AuthenticationDevice: &testAuthDevice{},
			DefaultExpiry:        expiry,
			DefaultInterval:      time.Second,
			MaxRequestedExpiry:   time.Minute,
			MinPollInterval:      time.Nanosecond,
		}
	})
	r := chi.NewRouter()
	a.Mount(r)
	srv = httptest.NewServer(r)
	t.Cleanup(srv.Close)
	client = registerCIBAClient(t, srv)
	resp := postBCAuthorize(t, srv, client, map[string]string{"scope": "files.read", "login_hint": "once@example.com"})
	defer func() { _ = resp.Body.Close() }()
	var bc struct {
		AuthReqID string `json:"auth_req_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bc); err != nil || bc.AuthReqID == "" {
		t.Fatalf("bc-authorize: %v %+v", err, bc)
	}
	return srv, client, bc.AuthReqID, a
}

func TestCIBATokensServedOnce(t *testing.T) {
	srv, client, id, a := approvedCIBA(t, 30*time.Second)

	pending := pollCIBAToken(t, srv, client, id)
	if code := oauthErrCode(t, pending); code != "authorization_pending" {
		t.Fatalf("pending poll: %q", code)
	}
	if err := a.ApproveBackchannelAuth(context.Background(), id, ulid.New()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	first := pollCIBAToken(t, srv, client, id)
	defer func() { _ = first.Body.Close() }()
	var tok theauth.TokenResponse
	if first.StatusCode != http.StatusOK || json.NewDecoder(first.Body).Decode(&tok) != nil || tok.AccessToken == "" {
		t.Fatalf("first poll: status %d token %+v", first.StatusCode, tok)
	}
	second := pollCIBAToken(t, srv, client, id)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("second poll status %d, want 400", second.StatusCode)
	}
	if code := oauthErrCode(t, second); code != "invalid_grant" {
		t.Fatalf("second poll error %q, want invalid_grant", code)
	}
}

func TestCIBAConcurrentPollsOneWinner(t *testing.T) {
	srv, client, id, a := approvedCIBA(t, 30*time.Second)
	if err := a.ApproveBackchannelAuth(context.Background(), id, ulid.New()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	const n = 32
	var ok, bad atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := pollCIBAToken(t, srv, client, id)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				ok.Add(1)
			} else {
				bad.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 || bad.Load() != n-1 {
		t.Fatalf("successes=%d failures=%d, want 1 and %d", ok.Load(), bad.Load(), n-1)
	}
}

func TestCIBAApprovedButExpiredIsExpired(t *testing.T) {
	srv, client, id, a := approvedCIBA(t, time.Second)
	if err := a.ApproveBackchannelAuth(context.Background(), id, ulid.New()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	resp := pollCIBAToken(t, srv, client, id)
	if code := oauthErrCode(t, resp); code != "expired_token" {
		t.Fatalf("expired approved poll: %q", code)
	}
}

func TestCIBADenyUnchangedAfterOnceFix(t *testing.T) {
	srv, client, id, a := approvedCIBA(t, 30*time.Second)
	if err := a.DenyBackchannelAuth(context.Background(), id, ulid.New()); err != nil {
		t.Fatalf("deny: %v", err)
	}
	for i := 0; i < 2; i++ {
		if code := oauthErrCode(t, pollCIBAToken(t, srv, client, id)); code != "access_denied" {
			t.Fatalf("deny poll %d: %q", i, code)
		}
	}
}

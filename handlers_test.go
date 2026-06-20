package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/go-chi/chi/v5"
)

func newTestServer(t *testing.T) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	a, _ := newTestAuth(t)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	theauth.SetBaseURLForTest(a, srv.URL)
	return srv, a
}

func TestMagicLinkRequestEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]string{"email": "h@h.com"})
	resp, err := http.Post(srv.URL+"/auth/magic-link", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestMeRequiresSession(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestEndToEndMagicLinkFlow(t *testing.T) {
	srv, a := newTestServer(t)
	ctx := context.Background()
	token, err := theauth.RequestMagicLinkForTest(a, ctx, "e2e@h.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/auth/magic-link/verify?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	req, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode != 200 {
		t.Fatalf("expected 200 on /me, got %d", meResp.StatusCode)
	}
	var me theauth.User
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Email != "e2e@h.com" {
		t.Fatalf("got email %q", me.Email)
	}
}

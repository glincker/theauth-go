package refresh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/provider/internal/refresh"
)

func TestDoSuccessAndRotation(t *testing.T) {
	var got map[string]string
	var user, pass string
	var basic bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = map[string]string{}
		for _, k := range []string{"grant_type", "refresh_token", "client_id", "client_secret", "scope"} {
			got[k] = r.Form.Get(k)
		}
		user, pass, basic = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at2","refresh_token":"rt2","expires_in":3600,"scope":"a b","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	tok, err := refresh.Do(context.Background(), refresh.Request{
		Provider: "x", TokenURL: srv.URL, ClientID: "cid", ClientSecret: "sec", RefreshToken: "rt1", Scope: "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at2" || tok.RefreshToken != "rt2" || tok.Scope != "a b" || tok.ExpiresAt.IsZero() {
		t.Fatalf("token = %+v", tok)
	}
	want := map[string]string{"grant_type": "refresh_token", "refresh_token": "rt1", "client_id": "cid", "client_secret": "sec", "scope": "a"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("form %s = %q, want %q", k, got[k], v)
		}
	}
	if basic {
		t.Error("credentials must be in the body by default")
	}

	if _, err := refresh.Do(context.Background(), refresh.Request{
		Provider: "x", TokenURL: srv.URL, ClientID: "cid", ClientSecret: "sec", RefreshToken: "rt1", BasicAuth: true,
	}); err != nil {
		t.Fatal(err)
	}
	if !basic || user != "cid" || pass != "sec" || got["client_secret"] != "" {
		t.Errorf("basic auth: %v %q %q secret-in-body=%q", basic, user, pass, got["client_secret"])
	}
}

func TestDoRevokedGrant(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		revoke bool
	}{
		{"invalid_grant 400", 400, `{"error":"invalid_grant","error_description":"expired"}`, true},
		{"github bad_refresh_token 200", 200, `{"error":"bad_refresh_token"}`, true},
		{"server error", 500, `oops`, false},
		{"invalid_client", 401, `{"error":"invalid_client"}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := refresh.Do(context.Background(), refresh.Request{Provider: "x", TokenURL: srv.URL, ClientID: "c", RefreshToken: "r"})
			if err == nil {
				t.Fatal("want error")
			}
			if got := errors.Is(err, theauth.ErrProviderGrantRevoked); got != tc.revoke {
				t.Fatalf("revoked = %v, want %v (%v)", got, tc.revoke, err)
			}
		})
	}
}

func TestDoWithoutRefreshToken(t *testing.T) {
	_, err := refresh.Do(context.Background(), refresh.Request{Provider: "x", TokenURL: "http://unused"})
	if !errors.Is(err, theauth.ErrProviderRefreshUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

package tokenvault_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/tokenvault"
)

func TestOAuthRefresher(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
		wantTok string
	}{
		{"ok", 200, `{"access_token":"new","refresh_token":"r2","expires_in":3600,"scope":"a b"}`, nil, "new"},
		{"invalid grant", 400, `{"error":"invalid_grant"}`, tokenvault.ErrInvalidGrant, ""},
		{"server error", 500, `oops`, errors.New("status 500"), ""},
		{"no access token", 200, `{}`, errors.New("no access token"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "rt" {
					w.WriteHeader(400)
					return
				}
				if u, p, ok := r.BasicAuth(); !ok || u != "id" || p != "secret" {
					w.WriteHeader(401)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			o := tokenvault.OAuthRefresher{TokenURL: srv.URL, ClientID: "id", ClientSecret: "secret", AllowInsecureHTTP: true}
			got, err := o.Refresh(context.Background(), "rt")
			switch {
			case tc.wantErr == nil && err != nil, tc.wantErr != nil && err == nil:
				t.Fatalf("err = %v", err)
			case errors.Is(tc.wantErr, tokenvault.ErrInvalidGrant) && !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v", err)
			case tc.wantErr != nil && strings.Contains(err.Error(), "rt"):
				t.Fatalf("error leaks token: %v", err)
			}
			if got.AccessToken != tc.wantTok {
				t.Fatalf("token = %q", got.AccessToken)
			}
		})
	}
	if _, err := (tokenvault.OAuthRefresher{TokenURL: "http://x.example/t"}).Refresh(context.Background(), "rt"); err == nil {
		t.Fatal("http token URL accepted without AllowInsecureHTTP")
	}
}

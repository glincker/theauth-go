package tokenvault_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go/v2/tokenvault"
)

func TestPresetsTable(t *testing.T) {
	seen := map[string]bool{}
	for key, p := range tokenvault.Presets {
		if p.ID == "" || p.ID != key {
			t.Errorf("preset %q has id %q", key, p.ID)
		}
		if seen[p.ID] {
			t.Errorf("duplicate id %q", p.ID)
		}
		seen[p.ID] = true
		for _, raw := range []string{p.AuthorizationURL, p.TokenURL, p.DocsURL} {
			if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" {
				t.Errorf("%s: %q is not an https URL", key, raw)
			}
		}
		if n := len(p.ExampleScopes); n < 2 || n > 3 {
			t.Errorf("%s: %d example scopes", key, n)
		}
	}
	if len(tokenvault.Presets) != 6 {
		t.Errorf("want 6 presets, got %d", len(tokenvault.Presets))
	}
}

func TestRefresherFromPreset(t *testing.T) {
	tests := []struct {
		id       string
		tokenURL string
		style    tokenvault.AuthStyle
	}{
		{"github", "https://github.com/login/oauth/access_token", tokenvault.AuthPost},
		{"google", "https://oauth2.googleapis.com/token", tokenvault.AuthPost},
		{"slack", "https://slack.com/api/oauth.v2.access", tokenvault.AuthPost},
		{"linear", "https://api.linear.app/oauth/token", tokenvault.AuthPost},
		{"microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/token", tokenvault.AuthPost},
		{"discord", "https://discord.com/api/oauth2/token", tokenvault.AuthBasic},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			r, err := tokenvault.RefresherFromPreset(tc.id, "cid", "sec", nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.TokenURL != tc.tokenURL || r.AuthStyle != tc.style || r.ClientID != "cid" {
				t.Fatalf("got %+v", r)
			}
		})
	}
	if _, err := tokenvault.RefresherFromPreset("nope", "a", "b", nil); err == nil {
		t.Fatal("unknown preset must fail")
	}
}

func TestOAuthRefresherAuthStyle(t *testing.T) {
	for _, style := range []tokenvault.AuthStyle{tokenvault.AuthBasic, tokenvault.AuthPost} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			user, pass, basic := r.BasicAuth()
			post := r.PostForm.Get("client_id") == "cid" && r.PostForm.Get("client_secret") == "sec"
			ok := (style == tokenvault.AuthBasic && basic && user == "cid" && pass == "sec" && !post) ||
				(style == tokenvault.AuthPost && !basic && post)
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"new"}`))
		}))
		r := tokenvault.OAuthRefresher{TokenURL: srv.URL, ClientID: "cid", ClientSecret: "sec", AuthStyle: style, AllowInsecureHTTP: true}
		if _, err := r.Refresh(context.Background(), "rt"); err != nil {
			t.Errorf("style %d: %v", style, err)
		}
		srv.Close()
	}
}

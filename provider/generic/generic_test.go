package generic

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
)

func TestCatalogProviders(t *testing.T) {
	tests := []struct {
		name string
		body string
		want theauth.ProviderUser
	}{
		{"spotify", `{"id":"sp1","email":"a@x.io","display_name":"Ann","images":[{"url":"https://i/1.png"}]}`,
			theauth.ProviderUser{ID: "sp1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/1.png"}},
		{"dropbox", `{"account_id":"dbid:1","email":"a@x.io","email_verified":true,"name":{"display_name":"Ann"},"profile_photo_url":"https://i/2.png"}`,
			theauth.ProviderUser{ID: "dbid:1", Email: "a@x.io", EmailVerified: true, Name: "Ann", AvatarURL: "https://i/2.png"}},
		{"zoom", `{"id":"z1","email":"a@x.io","display_name":"Ann","pic_url":"https://i/3.png"}`,
			theauth.ProviderUser{ID: "z1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/3.png"}},
		{"kakao", `{"id":4000000000123,"kakao_account":{"email":"a@x.io","is_email_verified":true,"profile":{"nickname":"Ann","profile_image_url":"https://i/4.png"}}}`,
			theauth.ProviderUser{ID: "4000000000123", Email: "a@x.io", EmailVerified: true, Name: "Ann", AvatarURL: "https://i/4.png"}},
		{"naver", `{"response":{"id":"n1","email":"a@x.io","nickname":"annie","profile_image":"https://i/5.png"}}`,
			theauth.ProviderUser{ID: "n1", Email: "a@x.io", Name: "annie", AvatarURL: "https://i/5.png"}},
		{"patreon", `{"data":{"id":"p1","attributes":{"email":"a@x.io","is_email_verified":false,"full_name":"Ann","image_url":"https://i/6.png"}}}`,
			theauth.ProviderUser{ID: "p1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/6.png"}},
		{"box", `{"id":"b1","login":"a@x.io","name":"Ann","avatar_url":"https://i/7.png"}`,
			theauth.ProviderUser{ID: "b1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/7.png"}},
		{"salesforce", `{"user_id":"005xx","email":"a@x.io","email_verified":true,"name":"Ann","picture":"https://i/8.png"}`,
			theauth.ProviderUser{ID: "005xx", Email: "a@x.io", EmailVerified: true, Name: "Ann", AvatarURL: "https://i/8.png"}},
		{"figma", `{"id":"f1","email":"a@x.io","handle":"Ann","img_url":"https://i/9.png"}`,
			theauth.ProviderUser{ID: "f1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/9.png"}},
		{"codeberg", `{"id":77,"email":"a@x.io","full_name":"","login":"ann","avatar_url":"https://i/10.png"}`,
			theauth.ProviderUser{ID: "77", Email: "a@x.io", Name: "ann", AvatarURL: "https://i/10.png"}},
	}
	if len(tests) != len(Names()) {
		t.Fatalf("test table covers %d providers, catalog has %d", len(tests), len(Names()))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := Lookup(tc.name)
			if !ok {
				t.Fatal("not in catalog")
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.PostForm.Get("code_verifier") != "ver" || r.PostForm.Get("grant_type") != "authorization_code" {
					t.Errorf("bad form %v", r.PostForm)
				}
				user, pass, hasBasic := r.BasicAuth()
				if spec.TokenBasicAuth {
					if !hasBasic || user != "cid" || pass != "sec" || r.PostForm.Get("client_secret") != "" {
						t.Errorf("want basic auth only, got %v %v", hasBasic, r.PostForm)
					}
				} else if hasBasic || r.PostForm.Get("client_secret") != "sec" {
					t.Errorf("want form credentials, got %v", r.PostForm)
				}
				_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","expires_in":3600}`))
			})
			mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer at" {
					t.Errorf("auth header %q", r.Header.Get("Authorization"))
				}
				wantMethod := spec.UserMethod
				if wantMethod == "" {
					wantMethod = http.MethodGet
				}
				if r.Method != wantMethod {
					t.Errorf("method %s want %s", r.Method, wantMethod)
				}
				_, _ = w.Write([]byte(tc.body))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			p, err := New(spec, Config{ClientID: "cid", ClientSecret: "sec", TokenURL: srv.URL + "/token", UserURL: srv.URL + "/user"})
			if err != nil {
				t.Fatal(err)
			}
			if p.Name() != tc.name {
				t.Fatalf("name %q", p.Name())
			}
			tok, err := p.ExchangeCode(t.Context(), "code", "ver", "https://app/cb")
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != "at" || tok.ExpiresAt.IsZero() {
				t.Fatalf("token %+v", tok)
			}
			got, err := p.UserInfo(t.Context(), tok)
			if err != nil {
				t.Fatal(err)
			}
			if *got != tc.want {
				t.Fatalf("got %+v want %+v", *got, tc.want)
			}
		})
	}
}

func TestAuthURL(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		scopes   []string
		wantScop string
		wantExtr string
	}{
		{"default scopes", "spotify", nil, "user-read-email", ""},
		{"caller scopes win", "spotify", []string{"a", "b"}, "a b", ""},
		{"comma separated", "figma", nil, "current_user:read", ""},
		{"extra params", "dropbox", nil, "account_info.read", "token_access_type=online"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewByName(tc.provider, Config{ClientID: "cid", ClientSecret: "sec"})
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(p.AuthURL("st", "chal", "https://app/cb", tc.scopes))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("scope") != tc.wantScop || q.Get("state") != "st" || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "cid" {
				t.Fatalf("query %v", q)
			}
			if tc.wantExtr != "" && !strings.Contains(u.RawQuery, tc.wantExtr) {
				t.Fatalf("missing %s in %s", tc.wantExtr, u.RawQuery)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	spec, _ := Lookup("box")
	tests := []struct {
		name   string
		cfg    Config
		spec   Spec
		status int
		body   string
		stage  string
	}{
		{"missing secret", Config{ClientID: "c"}, spec, 0, "", "new"},
		{"unknown name", Config{}, Spec{}, 0, "", "new"},
		{"token error body", Config{ClientID: "c", ClientSecret: "s"}, spec, 200, `{"error":"invalid_grant"}`, "token"},
		{"token http error", Config{ClientID: "c", ClientSecret: "s"}, spec, 500, `x`, "token"},
		{"user missing id", Config{ClientID: "c", ClientSecret: "s"}, spec, 200, `{"login":"a@x.io"}`, "user"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.stage == "user" && r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"at"}`))
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			tc.cfg.TokenURL, tc.cfg.UserURL = srv.URL+"/token", srv.URL+"/user"
			p, err := New(tc.spec, tc.cfg)
			if tc.stage == "new" {
				if err == nil {
					t.Fatal("want constructor error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tok, err := p.ExchangeCode(t.Context(), "c", "v", "r")
			if tc.stage == "token" {
				if err == nil {
					t.Fatal("want token error")
				}
				return
			}
			if _, err := p.UserInfo(t.Context(), tok); err == nil {
				t.Fatal("want userinfo error")
			}
		})
	}
	if _, err := NewByName("nope", Config{}); err == nil {
		t.Fatal("want unknown provider error")
	}
}

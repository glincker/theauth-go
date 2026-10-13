package generic

import (
	"io"
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
		{"linear", `{"data":{"viewer":{"id":"lin-1","name":"Ann","email":"a@x.io"}}}`,
			theauth.ProviderUser{ID: "lin-1", Email: "a@x.io", Name: "Ann"}},
		{"paypal", `{"user_id":"https://www.paypal.com/webapps/auth/identity/user/abc","name":"Ann","emails":[{"value":"a@x.io","primary":true}]}`,
			theauth.ProviderUser{ID: "https://www.paypal.com/webapps/auth/identity/user/abc", Email: "a@x.io", Name: "Ann"}},
		{"kick", `{"data":[{"user_id":4242,"name":"Ann","email":"a@x.io","profile_picture":"https://i/11.png"}],"message":"OK"}`,
			theauth.ProviderUser{ID: "4242", Email: "a@x.io", Name: "Ann", AvatarURL: "https://i/11.png"}},
		{"huggingface", `{"sub":"hf1","email":"a@x.io","email_verified":true,"name":"Ann","picture":"https://i/12.png"}`,
			theauth.ProviderUser{ID: "hf1", Email: "a@x.io", EmailVerified: true, Name: "Ann", AvatarURL: "https://i/12.png"}},
		{"vercel", `{"sub":"v1","email":"a@x.io","email_verified":true,"name":"Ann","preferred_username":"ann","picture":"https://i/13.png"}`,
			theauth.ProviderUser{ID: "v1", Email: "a@x.io", EmailVerified: true, Name: "Ann", AvatarURL: "https://i/13.png"}},
		{"yandex", `{"id":"y1","default_email":"a@x.io","real_name":"Ann","default_avatar_id":"abc/def"}`,
			theauth.ProviderUser{ID: "y1", Email: "a@x.io", Name: "Ann", AvatarURL: "https://avatars.yandex.net/get-yapic/abc/def/islands-200"}},
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
				wantVerifier := "ver"
				if spec.NoPKCE {
					wantVerifier = ""
				}
				if r.PostForm.Get("code_verifier") != wantVerifier || r.PostForm.Get("grant_type") != "authorization_code" {
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
				scheme := spec.UserAuthScheme
				if scheme == "" {
					scheme = "Bearer"
				}
				if r.Header.Get("Authorization") != scheme+" at" {
					t.Errorf("auth header %q", r.Header.Get("Authorization"))
				}
				if spec.UserBody != "" {
					b, _ := io.ReadAll(r.Body)
					if string(b) != spec.UserBody || r.Header.Get("Content-Type") != "application/json" {
						t.Errorf("userinfo body %q type %q", b, r.Header.Get("Content-Type"))
					}
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
		{"linear comma", "linear", []string{"read", "write"}, "read,write", ""},
		{"yandex comma", "yandex", nil, "login:email,login:info,login:avatar", ""},
		{"paypal flow entry", "paypal", nil, "openid email profile", "flowEntry=static"},
		{"kick default", "kick", nil, "user:read", ""},
		{"vercel default", "vercel", nil, "openid email profile", ""},
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
			wantMethod := "S256"
			if tc.provider == "paypal" {
				wantMethod = ""
				if q.Has("code_challenge") {
					t.Fatalf("paypal must not send code_challenge: %v", q)
				}
			}
			if q.Get("scope") != tc.wantScop || q.Get("state") != "st" || q.Get("code_challenge_method") != wantMethod || q.Get("client_id") != "cid" {
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

// tokenServer answers the token endpoint with body and records the request.
func tokenServer(t *testing.T, body string) (*httptest.Server, *http.Request) {
	t.Helper()
	var got http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = *r
		got.PostForm = r.PostForm
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestTokenScopeAsArray(t *testing.T) {
	srv, _ := tokenServer(t, `{"access_token":"at","scope":["read","write"],"expires_in":86399}`)
	p, err := NewByName("linear", Config{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.ExchangeCode(t.Context(), "code", "ver", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope != "read write" {
		t.Fatalf("scope %q", tok.Scope)
	}
}

func TestTokenScopeOddTypeDoesNotFail(t *testing.T) {
	srv, _ := tokenServer(t, `{"access_token":"at","scope":{"x":1}}`)
	p, _ := NewByName("kick", Config{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL})
	tok, err := p.ExchangeCode(t.Context(), "code", "ver", "https://app/cb")
	if err != nil || tok.AccessToken != "at" || tok.Scope != "" {
		t.Fatalf("tok %+v err %v", tok, err)
	}
}

func TestPayPalNoVerifierAndBasicAuth(t *testing.T) {
	srv, got := tokenServer(t, `{"access_token":"at","refresh_token":"rt","expires_in":28800}`)
	p, err := NewByName("paypal", Config{ClientID: "cid", ClientSecret: "sec", TokenURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.ExchangeCode(t.Context(), "code", "ver", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "rt" {
		t.Fatalf("refresh token %q", tok.RefreshToken)
	}
	user, pass, ok := got.BasicAuth()
	if !ok || user != "cid" || pass != "sec" {
		t.Fatalf("basic auth %v %q %q", ok, user, pass)
	}
	if got.PostForm.Has("code_verifier") || got.PostForm.Has("client_secret") {
		t.Fatalf("form %v", got.PostForm)
	}
}

func TestCatalogRefresh(t *testing.T) {
	tests := []struct {
		name  string
		basic bool
	}{
		{"linear", false}, {"kick", false}, {"huggingface", false}, {"vercel", false},
		{"yandex", false}, {"paypal", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, got := tokenServer(t, `{"access_token":"new","refresh_token":"rot","expires_in":3600,"scope":["a","b"]}`)
			p, err := NewByName(tc.name, Config{ClientID: "cid", ClientSecret: "sec", TokenURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			rp, ok := p.(theauth.RefreshProvider)
			if !ok {
				t.Fatal("not a RefreshProvider")
			}
			tok, err := rp.RefreshToken(t.Context(), "old")
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != "new" || tok.RefreshToken != "rot" || tok.Scope != "a b" {
				t.Fatalf("token %+v", tok)
			}
			if got.PostForm.Get("grant_type") != "refresh_token" || got.PostForm.Get("refresh_token") != "old" {
				t.Fatalf("form %v", got.PostForm)
			}
			_, _, hasBasic := got.BasicAuth()
			if hasBasic != tc.basic || (got.PostForm.Get("client_secret") == "") != tc.basic {
				t.Fatalf("basic=%v form=%v", hasBasic, got.PostForm)
			}
		})
	}
}

func TestVendorUserinfoFailures(t *testing.T) {
	tests := []struct {
		name, provider, body string
		status               int
	}{
		{"linear graphql error", "linear", `{"errors":[{"message":"AUTHENTICATION_ERROR"}],"data":null}`, 200},
		{"kick empty data", "kick", `{"data":[],"message":"OK"}`, 200},
		{"vercel unauthorized", "vercel", `{"error":"invalid_token"}`, 401},
		{"yandex unauthorized", "yandex", `{"error":"invalid_token"}`, 401},
		{"paypal no id", "paypal", `{"name":"Ann"}`, 200},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			p, err := NewByName(tc.provider, Config{ClientID: "c", ClientSecret: "s", UserURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.UserInfo(t.Context(), &theauth.ProviderToken{AccessToken: "at"}); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestCatalogIDsMatchNames(t *testing.T) {
	for _, n := range Names() {
		s, _ := Lookup(n)
		if s.Name != n {
			t.Errorf("catalog key %q has Spec.Name %q", n, s.Name)
		}
	}
}

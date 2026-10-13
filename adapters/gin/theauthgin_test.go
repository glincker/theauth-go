package theauthgin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage/memory"

	theauthgin "github.com/glincker/theauth-go/adapters/gin"
)

func newAuth(t *testing.T, responder func(http.ResponseWriter, *http.Request, int, string, string)) (*theauth.TheAuth, *http.Cookie) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", ErrorResponder: responder,
		APITokens: &theauth.APITokensConfig{Prefix: "tk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	u, err := store.CreateUser(ctx, theauth.User{Email: "ada@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := crypto.NewToken()
	if _, err := store.CreateSession(ctx, theauth.Session{
		ID: u.ID, UserID: u.ID, TokenHash: crypto.HashToken(raw),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return a, &http.Cookie{Name: "theauth_session", Value: raw}
}

func engine(a *theauth.TheAuth) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/anon", theauthgin.Authn(a), func(c *gin.Context) {
		_, ok := theauthgin.User(c)
		c.String(200, fmt.Sprint(ok))
	})
	r.GET("/me", theauthgin.RequireAuth(a), func(c *gin.Context) {
		u, _ := theauthgin.User(c)
		_, hasSess := theauthgin.Session(c)
		c.String(200, "%s %v", u.Email, hasSess)
	})
	r.GET("/ability", theauthgin.RequireAbility(a, "deploy"), func(c *gin.Context) { c.Status(204) })
	theauthgin.Mount(a, r, "/api")
	return r
}

func do(h http.Handler, path string, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMiddleware(t *testing.T) {
	a, cookie := newAuth(t, nil)
	r := engine(a)
	if rec := do(r, "/anon", nil); rec.Body.String() != "false" {
		t.Fatalf("anon: %d %q", rec.Code, rec.Body)
	}
	if rec := do(r, "/me", cookie); rec.Code != 200 || rec.Body.String() != "ada@example.com true" {
		t.Fatalf("me: %d %q", rec.Code, rec.Body)
	}
	rec := do(r, "/me", nil)
	if rec.Code != 401 || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("default 401: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := do(r, "/ability", nil); rec.Code != 401 {
		t.Fatalf("ability without credentials: %d", rec.Code)
	}
}

func TestErrorResponderIsUsed(t *testing.T) {
	a, _ := newAuth(t, func(w http.ResponseWriter, _ *http.Request, status int, code, _ string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"err":%q}`, code)
	})
	rec := do(engine(a), "/me", nil)
	if rec.Code != 401 || rec.Body.String() != `{"err":"auth.unauthenticated"}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestMountUnderPrefix(t *testing.T) {
	a, cookie := newAuth(t, nil)
	rec := do(engine(a), "/api/auth/me", cookie)
	if rec.Code != 200 {
		t.Fatalf("/api/auth/me: %d %s", rec.Code, rec.Body)
	}
}

func ExampleMount() {
	a, _ := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost"})
	defer a.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	theauthgin.Mount(a, r, "/api")
	r.GET("/dashboard", theauthgin.RequireAuth(a), func(c *gin.Context) { c.String(200, "ok") })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/dashboard", nil))
	fmt.Println(rec.Code)
	// Output: 401
}

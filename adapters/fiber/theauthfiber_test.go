package theauthfiber_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/gofiber/fiber/v2"

	theauthfiber "github.com/glincker/theauth-go/adapters/fiber"
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

func engine(a *theauth.TheAuth) *fiber.App {
	app := fiber.New()
	app.Get("/anon", theauthfiber.Authn(a), func(c *fiber.Ctx) error {
		_, ok := theauthfiber.User(c)
		return c.SendString(fmt.Sprint(ok))
	})
	app.Get("/me", theauthfiber.RequireAuth(a), func(c *fiber.Ctx) error {
		u, _ := theauthfiber.User(c)
		_, hasSess := theauthfiber.Session(c)
		return c.SendString(fmt.Sprintf("%s %v", u.Email, hasSess))
	})
	app.Get("/ability", theauthfiber.RequireAbility(a, "deploy"), func(c *fiber.Ctx) error { return c.SendStatus(204) })
	theauthfiber.Mount(a, app, "/api")
	return app
}

type result struct {
	Code        int
	Body        string
	ContentType string
}

func do(app *fiber.App, path string, c *http.Cookie) result {
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	res, err := app.Test(req, -1)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return result{res.StatusCode, string(b), res.Header.Get("Content-Type")}
}

func TestMiddleware(t *testing.T) {
	a, cookie := newAuth(t, nil)
	r := engine(a)
	if rec := do(r, "/anon", nil); rec.Body != "false" {
		t.Fatalf("anon: %d %q", rec.Code, rec.Body)
	}
	if rec := do(r, "/me", cookie); rec.Code != 200 || rec.Body != "ada@example.com true" {
		t.Fatalf("me: %d %q", rec.Code, rec.Body)
	}
	rec := do(r, "/me", nil)
	if rec.Code != 401 || rec.ContentType != "application/problem+json" {
		t.Fatalf("default 401: %d %s", rec.Code, rec.ContentType)
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
	if rec.Code != 401 || rec.Body != `{"err":"auth.unauthenticated"}` {
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
	app := fiber.New()
	theauthfiber.Mount(a, app, "/api")
	app.Get("/dashboard", theauthfiber.RequireAuth(a), func(c *fiber.Ctx) error { return c.SendString("ok") })

	res, _ := app.Test(httptest.NewRequest("GET", "/dashboard", nil), -1)
	fmt.Println(res.StatusCode)
	// Output: 401
}

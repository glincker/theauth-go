package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// ExampleTheAuth_Mount mounts the standard authentication routes onto a
// chi router. The routes appear under /auth (see Mount godoc for the
// complete list).
func ExampleTheAuth_Mount() {
	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      "http://localhost:8080",
		SecureCookie: false,
	})
	if err != nil {
		panic(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)
	fmt.Println("mounted")
	// Output: mounted
}

// ExampleTheAuth_Authn wraps a handler with the Authn middleware, which
// resolves the session cookie (when present) and attaches the user to the
// request context without rejecting anonymous traffic.
func ExampleTheAuth_Authn() {
	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      "http://localhost:8080",
		SecureCookie: false,
	})
	if err != nil {
		panic(err)
	}
	defer a.Close()

	handler := a.Authn()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := theauth.UserFromContext(r.Context()); ok {
			_, _ = w.Write([]byte("authed"))
			return
		}
		_, _ = w.Write([]byte("anon"))
	}))
	_ = handler
	fmt.Println("wired")
	// Output: wired
}

// ExampleNew shows the minimum wiring required to construct a TheAuth
// instance. Storage and BaseURL are the only mandatory fields; everything
// else takes a documented default.
func ExampleNew() {
	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      "http://localhost:8080",
		SecureCookie: false,
	})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	fmt.Println("ready")
	// Output: ready
}

// ExampleTheAuth_CreateUser creates a user for an existing identity. A repeat call with the same
// email (in any letter case) returns the same user, and a different ID for that email is a typed
// conflict.
func ExampleTheAuth_CreateUser() {
	a, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost:8080"})
	if err != nil {
		panic(err)
	}
	defer a.Close()

	ctx := context.Background()
	first, _ := a.CreateUser(ctx, theauth.CreateUserInput{Email: "Ada@Example.com", Name: "Ada"})
	again, _ := a.CreateUser(ctx, theauth.CreateUserInput{Email: "ada@example.com"})
	fmt.Println(first.Email, first.ID == again.ID)

	_, err = a.CreateUser(ctx, theauth.CreateUserInput{Email: "ada@example.com", ID: ulid.Make()})
	fmt.Println(errors.Is(err, theauth.ErrUserEmailConflict))
	// Output:
	// ada@example.com true
	// true
}

package theauth_test

import (
	"fmt"
	"net/http"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
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

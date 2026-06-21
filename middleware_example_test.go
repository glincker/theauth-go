package theauth_test

import (
	"fmt"
	"net/http"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

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

package theauth_test

import (
	"fmt"

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

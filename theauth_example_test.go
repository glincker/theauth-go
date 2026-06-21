package theauth_test

import (
	"fmt"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

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

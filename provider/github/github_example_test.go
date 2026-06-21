package github_test

import (
	"fmt"

	"github.com/glincker/theauth-go/provider/github"
)

// ExampleNew constructs a GitHub OAuth provider with the minimum required
// configuration. Pass the returned value into theauth.Config.Providers.
func ExampleNew() {
	p := github.New(github.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	})
	fmt.Println(p.Name())
	// Output: github
}

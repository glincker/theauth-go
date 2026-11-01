# Quick start: agent identity and delegation

Give an agent its own credential, then let it act for a user with a narrower scope. This needs `Config.AuthorizationServer` (which requires a 32 byte `EncryptionKey`) and `Config.AgentIdentity`, on a storage backend with agent identity support (memory, SQLite, Postgres or MySQL). `RegisterAgent` creates the agent and, because `Resource` is set, a delegation grant from the user to the agent in one call.

```go
package main

import (
	"context"
	"log"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func main() {
	ctx := context.Background()
	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       "https://as.example.com",
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32 bytes, load from your secrets manager
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: "https://as.example.com",
			Resources: []theauth.ProtectedResource{
				{Identifier: "https://api.example.com", Scopes: []string{"read", "write"}},
			},
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// The human who owns the agent. In a real app this is a signed-in user.
	user, err := a.UserByID(ctx, ownerID)
	if err != nil {
		log.Fatal(err)
	}

	// 1. Create the agent and a delegation grant for "read" on one resource.
	reg, err := a.RegisterAgent(ctx, theauth.RegisterAgentInput{
		OwnerID:  user.ID,
		Name:     "report-bot",
		Scope:    []string{"read"},
		Resource: "https://api.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	// reg.Secret.ClientID and reg.Secret.Secret are the agent's credential.
	// The secret is shown once and only its Argon2id hash is stored.

	// 2. The agent authenticates as itself (client credentials).
	self, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     reg.Secret.ClientID,
		ClientSecret: reg.Secret.Secret,
		Resource:     "https://api.example.com",
		Scope:        []string{"read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = self.AccessToken // sub is "agent:<id>"

	// 3. The agent trades a user's access token for a delegated one
	// (RFC 8693). The result carries the user as sub and the agent in act.
	delegated, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         reg.Secret.ClientID,
		ClientSecret:     reg.Secret.Secret,
		SubjectToken:     userAccessToken, // issued to the user by this authorization server
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Resource:         "https://api.example.com",
		Scope:            []string{"read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("delegated token expires in", delegated.ExpiresIn, "seconds")
}
```

`ownerID` and `userAccessToken` stand in for values from your sign-in flow (the user's ULID and an access token the authorization server issued to that user). Revoke access at any point with `RevokeDelegation`, `SuspendAgent` or `RevokeAgent`; resource servers see the change on their next introspection. Details: [Agent identity and revocation](https://docs.theauth.dev/go/concepts/agent-identity), [Agent delegation](https://docs.theauth.dev/go/guides/agent-delegation) and [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server).

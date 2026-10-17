// Command agent-policy shows an autonomy denylist enforced as an IAM Deny on
// an agent. The agent is registered with scopes that include payments.refund,
// but its attached policy denies that action, so the token endpoint refuses to
// mint it. Nothing here depends on a prompt.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/agentpolicy"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const resource = "https://api.example.com/mcp"

func main() {
	ctx := context.Background()

	denylist := policy.Policy{
		Version: policy.Version,
		ID:      "autonomy-denylist-v1",
		Statements: []policy.Statement{{
			ID:        "no-irreversible-actions",
			Effect:    policy.Deny,
			Actions:   []string{"payments.refund", "records.delete"},
			Resources: []string{"*"},
		}},
	}
	engine, err := agentpolicy.New(agentpolicy.Config{
		// A deny only policy needs DenyList mode. The default AllowList mode
		// refuses a set with no allow statement. Either way the agent's
		// registered scopes still cap what it can get.
		Mode:     agentpolicy.DenyList,
		Policies: []policy.Policy{denylist},
		// Per agent budget from your IAM store. Here the support agent gets
		// 10 mints a minute; agents with no override use the config wide limit.
		ResolverV2: func(_ context.Context, ag theauth.Agent) (agentpolicy.Resolution, error) {
			if ag.Name == "support-agent" {
				return agentpolicy.Resolution{RateLimit: &theauth.AgentRateLimit{Requests: 10, Per: time.Minute}}, nil
			}
			return agentpolicy.Resolution{}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	store := memory.New()
	auth, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			DisableRotation: true,
			Resources: []theauth.ProtectedResource{{
				Identifier: resource,
				Scopes:     []string{"tickets.read", "payments.refund", "records.delete"},
			}},
		},
		AgentIdentity: &theauth.AgentConfig{
			PolicyEngine: engine,
			RateLimit:    theauth.AgentRateLimit{Requests: 30, Per: time.Minute, Burst: 5},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	owner, err := store.CreateUser(ctx, theauth.User{Email: "owner@example.com"})
	if err != nil {
		log.Fatal(err)
	}
	_, secret, err := auth.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &owner.ID},
		Name:  "support-agent",
		Scope: []string{"tickets.read", "payments.refund", "records.delete"},
	})
	if err != nil {
		log.Fatal(err)
	}
	mint := func(scope ...string) (theauth.TokenResponse, error) {
		return auth.ClientCredentialsToken(ctx, theauth.TokenRequest{
			GrantType: theauth.GrantTypeClientCredentials, ClientID: secret.ClientID,
			ClientSecret: secret.Secret, Resource: resource, Scope: scope,
		})
	}

	// Asking for a denied action by name fails.
	_, err = mint("tickets.read", "payments.refund")
	fmt.Println("refund requested:", errors.Is(err, theauth.ErrAgentPolicyDenied), err)

	// A default mint is narrowed to what policy permits.
	tok, err := mint()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("default scope:", tok.Scope)
}

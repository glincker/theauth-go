# Deny risky actions for AI agents with IAM policies

Telling an agent in its prompt never to issue refunds is a request, not a control, because a model can be talked out of it.

In this tutorial you attach an IAM policy to an agent so the token endpoint refuses to mint a token that carries `payments.refund`, whatever scopes the agent was registered with. Then you look at the `agent_policy` claim, a per-agent rate limit, and what happens when your policy lookup is down.

## Prerequisites

- Go 1.25 or newer.
- An authorization server with `AgentIdentity` enabled. The demo uses the in-memory store.

```sh
go get github.com/glincker/theauth-go/v2@latest
```

Agent policies and rate limits ship in the next release after v2.10.0. Until it is tagged, use `@main`.

## 1. Write the policy

A policy is a document with statements. This one denies two irreversible actions on every resource.

```go
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
```

Deny always wins over allow.

## 2. Pick DenyList or AllowList

`agentpolicy.Config.Mode` decides what happens to an action no statement matches. `AllowList` is the default: nothing passes unless an `allow` statement covers it. `DenyList` lets unmatched actions through and only `deny` and `escalate` statements restrict. A set with no allow statement is refused in the default mode, on purpose, so for a denylist you say `DenyList`.

```go
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
```

The resolver is where a per-agent policy set or rate limit comes from, usually your IAM store. Here the support agent gets 10 mints a minute. Neither mode widens access: the agent's registered scopes, the resource catalog and any delegation grant still cap what a token can carry. Policy runs last and only removes scopes.

## 3. Wire it into the server

```go
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
```

`AgentConfig.RateLimit` is the default budget for every agent: a token bucket per agent id.

## 4. Create an agent and try to mint

The agent is registered with `payments.refund` and `records.delete` in its scopes. Policy overrides that.

```go
	owner, err := store.CreateUser(ctx, theauth.User{Email: "owner@example.com"})
	if err != nil {
		log.Fatal(err)
	}
	ag, secret, err := auth.CreateAgent(ctx, theauth.CreateAgentInput{
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
```

## 5. Read the claim and check at call time

The access token records which policies vetted it. A resource server that knows the agent id can also ask the same question the token endpoint asks.

```go
	// The token records which policies vetted it.
	parts := strings.Split(tok.AccessToken, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	ap, _ := json.Marshal(claims["agent_policy"])
	fmt.Println("agent_policy claim:", string(ap))

	// AllowList is the default, and a deny only set is refused at startup.
	_, err = agentpolicy.New(agentpolicy.Config{Policies: []policy.Policy{denylist}})
	fmt.Println("allow list with no allow:", errors.Is(err, agentpolicy.ErrNoAllowStatement))

	// The same question at call time, with a per agent budget.
	err = auth.AuthorizeAgent(ctx, ag.ID.String(), "payments.refund", "acct/9")
	var denied *theauth.AgentPolicyDeniedError
	fmt.Println("AuthorizeAgent refund denied:", errors.As(err, &denied))
}
```

## What the output means

```text
refund requested: true theauth: access_denied: agent policy does not permit action "payments.refund"
default scope: tickets.read
agent_policy claim: {"hash":"516eed57c6a3ebe2315d47329ce5756cc819cef71135abc5948ee0d96942583f","ids":["autonomy-denylist-v1"]}
allow list with no allow: true
AuthorizeAgent refund denied: true
```

Asking for `payments.refund` by name is an `access_denied` that names the action and nothing else; the policy id and statement id go to the audit log, not the client. A mint with no scope requested gets the default set, narrowed to what policy allows, so the agent ends up with `tickets.read`. The claim holds the policy ids and a SHA-256 of the documents, so a token can be tied to the exact rules. Give each policy a stable `id` and change it when the text changes.

## Rate limits and a resolver outage

Two more behaviors are in the tests and worth seeing. Save this as a second program. It uses a resolver that fails, and a limit of two requests a minute checked with `AuthorizeAgent`, which spends the same budget as a mint.

```go
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

func boot(engine *agentpolicy.Engine, rl theauth.AgentRateLimit) (*theauth.TheAuth, theauth.Agent, theauth.AgentSecret) {
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	store := memory.New()
	auth, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: "https://auth.example.com", DisableRotation: true,
			Resources: []theauth.ProtectedResource{{Identifier: resource, Scopes: []string{"tickets.read"}}},
		},
		AgentIdentity: &theauth.AgentConfig{PolicyEngine: engine, RateLimit: rl},
	})
	if err != nil {
		log.Fatal(err)
	}
	owner, _ := store.CreateUser(ctx, theauth.User{Email: "owner@example.com"})
	ag, secret, err := auth.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &owner.ID}, Name: "support-agent", Scope: []string{"tickets.read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	return auth, ag, secret
}

func mint(auth *theauth.TheAuth, s theauth.AgentSecret) error {
	_, err := auth.ClientCredentialsToken(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeClientCredentials, ClientID: s.ClientID,
		ClientSecret: s.Secret, Resource: resource, Scope: []string{"tickets.read"},
	})
	return err
}

func main() {
	// A resolver that cannot reach the IAM store.
	down, err := agentpolicy.New(agentpolicy.Config{
		Mode: agentpolicy.DenyList,
		Resolver: func(context.Context, theauth.Agent) ([]policy.Policy, error) {
			return nil, errors.New("iam store down")
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	auth, _, secret := boot(down, theauth.AgentRateLimit{})
	defer auth.Close()
	err = mint(auth, secret)
	fmt.Println("mint with resolver down:", err)

	// Two checks a minute, the third is limited.
	quiet, _ := agentpolicy.New(agentpolicy.Config{})
	auth2, ag2, _ := boot(quiet, theauth.AgentRateLimit{Requests: 2, Per: time.Minute})
	defer auth2.Close()
	for i := 1; i <= 3; i++ {
		err := auth2.AuthorizeAgent(context.Background(), ag2.ID.String(), "tickets.read", "acct/9")
		var limited *theauth.AgentRateLimitedError
		if errors.As(err, &limited) {
			fmt.Printf("check %d: rate limited, retry after about %ds\n", i, int(limited.RetryAfter.Seconds()+0.5))
			continue
		}
		fmt.Printf("check %d: err=%v\n", i, err)
	}
}
```

```text
mint with resolver down: theauth: temporarily_unavailable: resolve policies for agent 01M53JD13SFGTQRD8VJASTENBY: agentpolicy: resolver: iam store down
check 1: err=<nil>
check 2: err=<nil>
check 3: rate limited, retry after about 30s
```

(The agent id differs on each run. Over HTTP the first message is a `503 temporarily_unavailable` with `Retry-After`, and the cause is not shown to the client.)

A resolver error, an invalid policy document or an invalid rate limit fails the mint closed. You see it in the `agent.policy_resolver_failed` audit event and the `theauth_agent_policy_resolver_errors_total` counter. The resolver runs only inside agent token mints and `AuthorizeAgent`. Sessions, human login, session links and API tokens never call it, so an outage cannot lock people out.

## Limits

- Per-agent policy references and rate limits are not stored on the agent row. Keep the mapping in your IAM store and return it from the resolver. It runs on every agent mint, so keep it fast or cache it.
- The limiter lives in the process. With several replicas, each enforces its own budget.
- An `escalate` statement counts as a refusal at mint time, since a token endpoint cannot ask a human. Use `policy/toolguard` for approval at call time.
- In DenyList mode an action no statement names passes, so list every irreversible action you care about.

## Next

- [Agent policies and rate limits reference](../agent-policies.md)
- [Example: examples/agent-policy](https://github.com/glincker/theauth-go/tree/main/examples/agent-policy)
- [The tests](https://github.com/glincker/theauth-go/blob/main/internal/as/agent_policy_test.go) cover token exchange, concurrency and audit events.
- [Require a passkey or TOTP before a risky AI action](passkey-or-totp-before-risky-ai-action.md)

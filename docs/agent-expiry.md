# Agent expiry

An agent can carry an optional expiry. Past it, the agent is treated as inactive everywhere, and no token minted for it can outlive it. Use it for short lived automation, trials and contractor agents, where "remember to revoke it" is not a plan.

With no expiry set, nothing changes: agents live until you suspend or revoke them.

## Set an expiry

```go
exp := time.Now().Add(30 * 24 * time.Hour)
agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
    Owner:     theauth.AgentOwner{UserID: &uid},
    Name:      "q4-report-bot",
    Scope:     []string{"files.read"},
    ExpiresAt: &exp,
})

// Move it later, shorten it, or clear it with nil.
err = a.SetAgentExpiry(ctx, agent.ID, &newExp)
err = a.SetAgentExpiry(ctx, agent.ID, nil)
```

The value must be in the future and no more than 10 years ahead (`models.MaxAgentLifetime`). Otherwise both calls return `ErrAgentExpiryInvalid`. `SetAgentExpiry` drops the cached client and chain entries and emits `agent.expiry_changed`. Extending the expiry of an expired agent revives it, unless it was also suspended or revoked.

## What an expired agent cannot do

`ErrAgentExpired` wraps `ErrAgentInactive`, so existing `errors.Is(err, theauth.ErrAgentInactive)` checks keep matching. Test for `ErrAgentExpired` first when you want the reason (`agent_expired`). On the wire it is the same `access_denied` a suspended agent gets.

| Where | Behavior |
| --- | --- |
| `client_credentials` | Refused with `ErrAgentExpired`. |
| Token exchange (RFC 8693) | Refused when the requesting agent is expired, or when any agent already in the subject token's actor chain is expired. An expired agent in a chain cannot lend permissions. |
| JWT bearer, when the client is an agent | Refused with `ErrAgentExpired`. |
| Introspection | `active=false` for a token whose subject agent, or any agent in its `act` chain, is expired, even if the token itself has not reached `exp`. |
| Agent gate (`Authorize`, policy and rate limit checks) | Returns `agent.ErrAgentExpired`, which wraps `ErrAgentNotActive`. |
| `GrantDelegation` | Refused for an expired agent. |

## Token lifetime cap

An access token minted for an agent never outlives it. `exp` is the earliest of the usual bounds (access token TTL, delegation `MaxDurationSeconds`, subject token `exp`) and the expiry of every agent involved: the minting agent and every agent in the delegation chain. `expires_in` in the response reflects the cap.

The chain walk cache (`chainCacheTTL`, 60 seconds) remembers the earliest agent expiry in the chain, so a cached "active" answer is never served past it. Introspection responses are cached for `IntrospectionCacheTTL`. Because the token `exp` is capped, the only window left is that cache, and it is bounded by the TTL you configured.

## Time source

Introspection and chain checks read `AuthorizationServerConfig.Clock`, so tests can step past an expiry without sleeping. The agent service validates a new expiry against the wall clock.

## Storage

Every bundled backend persists `expires_at` in a nullable column and needs no backfill. Apply the migration before you run a build that includes this feature.

| Backend | Migration | Column |
| --- | --- | --- |
| Postgres | `0031_agent_expiry` (up and down) | `agents.expires_at timestamptz` |
| MySQL | `0030_agent_expiry` | `agents.expires_at DATETIME(6) NULL` |
| SQLite | `0035_agent_expiry` | `theauth_agents.expires_at INTEGER` (unix microseconds) |

If you implement `OAuthServerStorage` yourself, add `UpdateAgentExpiry(ctx, id, *time.Time)`, return `ExpiresAt` from every agent read, and accept it in `InsertAgent`. `storagetest.RunAgents` covers the round trip, the nil default and the update.

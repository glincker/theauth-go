# Token vault

```go
keys, _ := tokenvault.NewKeyRing("2026-10", map[string][]byte{"2026-10": key32}) // key32 is 32 bytes from your KMS
store := memory.New()

v, _ := tokenvault.New(tokenvault.Config{
	Store:       store,                                   // theauth.TokenVaultStorage
	Keys:        keys,
	Delegations: tokenvault.GrantDelegations{Store: store},
	Audit:       tokenvault.AuditStorageSink{Store: store},
	Providers: map[string]tokenvault.Refresher{
		"acme": tokenvault.OAuthRefresher{TokenURL: "https://acme.example/oauth/token", ClientID: id, ClientSecret: secret},
	},
})

// After the user completes the provider's OAuth flow:
v.Connect(ctx, tokenvault.ConnectInput{UserID: uid, Provider: "acme", AccessToken: at, RefreshToken: rt,
	ExpiresAt: exp, Scopes: []string{"calendar.read"}})

// In the agent's tool call:
tok, err := v.AccessToken(ctx, tokenvault.Request{AgentID: aid, UserID: uid, Provider: "acme", Scopes: []string{"calendar.read"}})
// use tok.Token as a Bearer token
```

Runnable program with a stub provider: [examples/token-vault](../examples/token-vault/main.go).

The vault stores a user's third party OAuth credentials encrypted at rest. Agents get short-lived access tokens. The refresh token never leaves the vault.

## Checks per request

| Step | Check |
|------|-------|
| 1 | At least one scope is requested. |
| 2 | The user delegated the provider and every scope to this agent (`DelegationGrant`, resource `vault:<provider>`). Revoked, expired or mismatched grants are refused. |
| 3 | The connection exists, is not `needs_reauth`, and holds the scopes. |
| 4 | Within `ExpirySkew` (default 60 seconds) of expiry, the vault refreshes. `invalid_grant` sets `needs_reauth`. |
| 5 | Decrypt, write the audit event, then return the token. If the audit write fails, the token is withheld. |

## Provider presets

| Provider | Token URL | Refresh behavior | Quirk |
|---|---|---|---|
| github | `https://github.com/login/oauth/access_token` | Opt in | Tokens never expire unless token expiration is enabled; then 8 hour access, rotating refresh. |
| google | `https://oauth2.googleapis.com/token` | Authorize params | Needs `access_type=offline` and `prompt=consent`; refresh token usually only on first consent. |
| slack | `https://slack.com/api/oauth.v2.access` | Opt in | Rotation is per app and cannot be turned off; 12 hour access, single use refresh. |
| linear | `https://api.linear.app/oauth/token` | Always | 24 hour access; every refresh rotates the refresh token. |
| microsoft | `https://login.microsoftonline.com/common/oauth2/v2.0/token` | Scope | Request `offline_access` or no refresh token is issued. |
| discord | `https://discord.com/api/oauth2/token` | Always | Basic auth; implicit and client credentials grants return no refresh token. |

Notion and Atlassian are not preset because their token endpoints are documented with JSON bodies, which the vault refresh does not send.

`tokenvault.RefresherFromPreset("github", id, secret, nil)` builds the refresher with the right token URL and `AuthStyle`.

## Key rotation

1. Add the new key to the ring and make it active. Deploy.
2. Run `Vault.Rewrap` until it returns 0. It re-seals rows on older keys.
3. Remove the old key.

A blob that names a key missing from the ring fails with `ErrUnknownKey`.

## Security

- AES-256-GCM with a random 96-bit nonce per blob. Keys are 32 bytes, from a KMS or secret manager.
- Associated data binds each blob to its user, provider and field (`access` or `refresh`). A copied row fails to decrypt.
- Tokens never appear in logs, errors, audit events, or `String` output.
- Audit is fail closed for issuance. Denials are audited on a best effort basis.
- Refreshes are single flight per user and provider in one process. Across processes, a version compare and swap lets one writer win. If a provider rotates refresh tokens on every use, a losing node's refresh can surface as `needs_reauth`.
- `OAuthRefresher` requires an https token URL unless `AllowInsecureHTTP` is set. Use that for tests only.
- Return one generic refusal to the agent, so it cannot probe connections.

## Not implemented

- SQL storage (SQLite, Postgres, MySQL). Only `storage/memory` implements `TokenVaultStorage`.
- Cross node refresh locking beyond the version compare and swap.
- Rate limits per user or per agent, and a maximum token lifetime cap.
- Authorization code flow for the first credential. Call `Connect` with its result.
- Provider quirks such as non-standard endpoints, JSON refresh bodies, or PKCE. Implement `Refresher` for these.

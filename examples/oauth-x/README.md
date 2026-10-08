# oauth-x

Sign in with X (formerly Twitter) using the `provider/x` package. State is held in memory, so users and sessions are lost on restart.

## Run

```bash
X_CLIENT_ID=xxx X_CLIENT_SECRET=yyy go run .
```

Open <http://localhost:8091> and click the sign-in link.

## Setup

Register an app with X (formerly Twitter) and set its redirect URL to:

```
http://localhost:8091/auth/providers/x/callback
```

The header comment in `main.go` lists the scopes and console steps this provider needs. `BASE_URL` and `ADDR` override the default origin and listen address.

See [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) for the general flow.

X requires PKCE for OAuth 2.0, and the standard users endpoint does not return an email address without elevated API access, so the example shows the display name. For a public client, leave `X_CLIENT_SECRET` empty.

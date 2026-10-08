# oauth-bitbucket

Sign in with Bitbucket Cloud using the `provider/bitbucket` package. State is held in memory, so users and sessions are lost on restart.

## Run

```bash
BITBUCKET_CLIENT_ID=xxx BITBUCKET_CLIENT_SECRET=yyy go run .
```

Open <http://localhost:8088> and click the sign-in link.

## Setup

Register an app with Bitbucket Cloud and set its redirect URL to:

```
http://localhost:8088/auth/providers/bitbucket/callback
```

The header comment in `main.go` lists the scopes and console steps this provider needs. `BASE_URL` and `ADDR` override the default origin and listen address.

See [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) for the general flow.

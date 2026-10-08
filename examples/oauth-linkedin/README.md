# oauth-linkedin

Sign in with LinkedIn using the `provider/linkedin` package. State is held in memory, so users and sessions are lost on restart.

## Run

```bash
LINKEDIN_CLIENT_ID=xxx LINKEDIN_CLIENT_SECRET=yyy go run .
```

Open <http://localhost:8090> and click the sign-in link.

## Setup

Register an app with LinkedIn and set its redirect URL to:

```
http://localhost:8090/auth/providers/linkedin/callback
```

The header comment in `main.go` lists the scopes and console steps this provider needs. `BASE_URL` and `ADDR` override the default origin and listen address.

See [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) for the general flow.

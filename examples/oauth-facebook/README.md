# oauth-facebook

Sign in with Facebook using the `provider/facebook` package. State is held in memory, so users and sessions are lost on restart.

## Run

```bash
FACEBOOK_CLIENT_ID=xxx FACEBOOK_CLIENT_SECRET=yyy go run .
```

Open <http://localhost:8085> and click the sign-in link.

## Setup

Register an app with Facebook and set its redirect URL to:

```
http://localhost:8085/auth/providers/facebook/callback
```

The header comment in `main.go` lists the scopes and console steps this provider needs. `BASE_URL` and `ADDR` override the default origin and listen address.

See [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) for the general flow.

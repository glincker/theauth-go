# oauth-gitlab

Sign in with GitLab using the `provider/gitlab` package. State is held in memory, so users and sessions are lost on restart.

## Run

```bash
GITLAB_CLIENT_ID=xxx GITLAB_CLIENT_SECRET=yyy go run .
# self-hosted: add GITLAB_BASE_URL=https://git.example.com
```

Open <http://localhost:8087> and click the sign-in link.

## Setup

Register an app with GitLab and set its redirect URL to:

```
http://localhost:8087/auth/providers/gitlab/callback
```

The header comment in `main.go` lists the scopes and console steps this provider needs. `BASE_URL` and `ADDR` override the default origin and listen address.

See [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) for the general flow.

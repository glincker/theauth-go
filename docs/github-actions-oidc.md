# GitHub Actions OIDC login

A GitHub Actions job can ask GitHub for a short lived OIDC token and trade it at your token endpoint for a theauth access token. No stored secret, no glue code. It uses the existing RFC 7523 `jwt-bearer` grant plus required claim matchers on the trusted issuer.

## Read this first: restrict the issuer

GitHub signs the tokens of every repository on github.com with the same key, under the same issuer (`https://token.actions.githubusercontent.com`). Signature and issuer checks therefore prove only that the token came from some GitHub workflow, possibly one in a public repository an attacker created five minutes ago.

An issuer without required claims lets any of them authenticate. `GitHubActionsIssuer` refuses to build one: it returns `ErrGitHubActionsUnrestricted` unless you set `Repository` or `RepositoryOwner`. If you assemble a `TrustedJWTIssuer` for GitHub by hand, add the matchers yourself.

## Server setup

```go
iss, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{
    Repository:    "acme/app",                 // exact owner/name
    Refs:          []string{"refs/heads/main"}, // or one glob: "refs/heads/release/*"
    Environment:   "production",
    Audience:      "https://auth.example.com/gh",
    SubjectMapper: myWorkflowMapper{},          // GitHub's sub is not a ULID
})
if err != nil {
    log.Fatal(err)
}

cfg.AuthorizationServer = &theauth.AuthorizationServerConfig{
    Issuer:    "https://auth.example.com",
    Resources: resources,
    JWTBearer: &theauth.JWTBearerConfig{TrustedJWTIssuers: []theauth.TrustedJWTIssuer{iss}},
}
```

The constructor sets the issuer URL, the JWKS URL (`https://token.actions.githubusercontent.com/.well-known/jwks`, the `jwks_uri` in GitHub's discovery document), allows only `RS256` (the only algorithm GitHub's discovery document lists) and builds these matchers, all of which must pass:

| Option | Matcher |
| --- | --- |
| `RepositoryOwner` | `repository_owner` equals the value |
| `Repository` | `repository` equals the value |
| `Refs` | one entry: `ref` equals it, or matches it if it has `*`. Several entries: `ref` is one of them (exact only) |
| `Environment` | `environment` equals the value |

Append more to `iss.RequiredClaims` for anything else, for example `job_workflow_ref` to pin a workflow file, or `repository_id` and `repository_owner_id` to survive a rename or a re-registered name.

`Audience` is the `aud` the workflow must request. Leave it empty to require your authorization server issuer URL. GitHub puts whatever the job asked for in `aud`, so a custom audience is a good way to keep tokens minted for other services out of this one.

`SubjectMapper` decides which local user the token acts as. The built-in `SubMapper` expects a ULID in `sub`, which GitHub does not send (it sends strings like `repo:acme/app:ref:refs/heads/main`). Write a mapper that looks the workflow up, and read the verified claims it is given. When the request carries the client id of an agent, the agent's policy and rate limit apply to the mint as for any jwt-bearer grant.

## Workflow

```yaml
name: deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write   # lets the job request an OIDC token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Get a GitHub OIDC token
        run: |
          AUD="https://auth.example.com/gh"
          GH_TOKEN=$(curl -sS \
            -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$AUD" | jq -r .value)
          echo "::add-mask::$GH_TOKEN"
          echo "GH_TOKEN=$GH_TOKEN" >> "$GITHUB_ENV"

      - name: Exchange it for an access token
        run: |
          ACCESS=$(curl -sS https://auth.example.com/oauth/token \
            -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
            --data-urlencode "assertion=$GH_TOKEN" \
            -d resource=https://api.example.com/mcp \
            -d scope=api.read | jq -r .access_token)
          echo "::add-mask::$ACCESS"
          echo "ACCESS_TOKEN=$ACCESS" >> "$GITHUB_ENV"
```

`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` exist only when the job has `id-token: write`. Add `client_id=<agent client id>` to the exchange if the token should mint as an agent.

## What a denial looks like

If any matcher fails, or a claim is missing, the endpoint answers `invalid_grant` with the usual generic description. It never says which claim failed or what its value was, so a caller cannot probe your configuration. The operator gets an audit event:

```json
{"action": "jwt_bearer.claims_denied",
 "targetType": "jwt_issuer", "targetId": "https://token.actions.githubusercontent.com",
 "metadata": {"issuer": "...", "failed_claims": ["repository", "ref"], "agent_id": "...", "agent_name": "..."}}
```

`failed_claims` holds claim names only. `agent_id` and `agent_name` appear when the request names an agent client.

## Matching rules

See [jwt-bearer claim matchers](id-jag.md#required-claim-matchers) for the full list. In short: all matchers must pass, a missing claim fails, comparison is exact and case sensitive (`Acme/App` is not `acme/app`), and numbers or booleans never match a string matcher.

## What was and was not checked

The issuer URL, JWKS path, `RS256` and the claim names above were read from GitHub's live discovery document (`/.well-known/openid-configuration`), which lists `repository`, `repository_owner`, `repository_id`, `repository_owner_id`, `ref`, `ref_type`, `environment`, `job_workflow_ref`, `workflow`, `actor`, `sha`, `run_id`, `event_name`, `sub` and `jti`, among others. Tests never touch the network; they sign tokens with a local key. The request-token flow in the workflow snippet follows GitHub's documentation as I know it and has not been run against GitHub from this repository. Check how long GitHub tokens live against `AssertionMaxAge` (default 300 seconds) before depending on slow jobs.

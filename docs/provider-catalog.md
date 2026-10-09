# Provider catalog and generic OIDC

## Table-driven providers

`provider/generic` builds a `theauth.Provider` from a `Spec`: three URLs, default scopes and the JSON paths of the profile fields. Ten providers ship in the table.

| Name | Notes |
|---|---|
| `spotify` | client secret in Basic auth |
| `dropbox` | POST userinfo, email verified flag mapped |
| `zoom` | client secret in Basic auth |
| `kakao` | nested profile, email verified flag mapped |
| `naver` | profile under `response` |
| `patreon` | identity v2 with explicit fields, email verified flag mapped |
| `box` | email comes from `login` |
| `salesforce` | OpenID userinfo, email verified flag mapped |
| `figma` | comma separated scopes |
| `codeberg` | override the URLs to target any Gitea or Forgejo host |

```go
p, err := generic.NewByName("spotify", generic.Config{
	ClientID:     os.Getenv("SPOTIFY_ID"),
	ClientSecret: os.Getenv("SPOTIFY_SECRET"),
})
```

`EmailVerified` is true only where the provider says so. Providers that do not report it return false, so account linking will not trust their email addresses.

For a provider that is not in the table, pass your own spec:

```go
p, err := generic.New(generic.Spec{
	Name:     "acme",
	AuthURL:  "https://acme.example/oauth/authorize",
	TokenURL: "https://acme.example/oauth/token",
	UserURL:  "https://acme.example/api/me",
	Scopes:   []string{"profile", "email"},
	Fields: generic.Fields{
		ID:    []string{"user.id"},
		Email: []string{"user.email"},
		Name:  []string{"user.name", "user.login"},
	},
}, generic.Config{ClientID: id, ClientSecret: secret})
```

Paths are dotted; a numeric segment indexes an array (`images.0.url`). The first non-empty alternative wins. Providers that need a second request for the email, a form-encoded token response or a signed ID token do not fit and keep their own package.

## OIDC discovery overrides

`provider/oidc` discovers endpoints from `<issuer>/.well-known/openid-configuration`. Two fields cover IdPs that do not follow that layout:

```go
p, err := oidc.New(ctx, oidc.Config{
	Issuer:       "https://idp.example.com",
	ClientID:     id,
	ClientSecret: secret,
	// Document lives elsewhere (the issuer inside it must still match).
	DiscoveryURL: "https://idp.example.com/tenants/42/.well-known/openid-configuration",
	// Replace single endpoints after discovery.
	Endpoints: oidc.Endpoints{UserinfoEndpoint: "https://idp.example.com/v2/userinfo"},
})
```

With `DisableDiscovery: true` no request is made and you must set `AuthorizationEndpoint`, `TokenEndpoint` and `JWKSURI`. Overrides must be https unless `AllowInsecureHTTP` is set (tests and local IdPs only). ID token checks (signature, issuer, audience, nonce) are unchanged.

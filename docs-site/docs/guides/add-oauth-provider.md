# Add an OAuth Provider

theauth-go ships built-in providers for GitHub, Google, Microsoft, and Discord. Each provider is a separate subpackage under `provider/`.

## Install a provider

```bash
go get github.com/glincker/theauth-go
```

All provider packages are included in the main module. No separate install is needed.

## Wire a provider

```go
import (
    "github.com/glincker/theauth-go"
    "github.com/glincker/theauth-go/provider/github"
    "github.com/glincker/theauth-go/storage/postgres"
)

a, _ := theauth.New(theauth.Config{
    Storage: store,
    BaseURL: "https://myapp.com",
    Providers: []theauth.Provider{
        github.New(github.Config{
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        }),
    },
})
```

## Available providers

| Provider | Package |
|---|---|
| GitHub | `github.com/glincker/theauth-go/provider/github` |
| Google | `github.com/glincker/theauth-go/provider/google` |
| Microsoft | `github.com/glincker/theauth-go/provider/microsoft` |
| Discord | `github.com/glincker/theauth-go/provider/discord` |

Each exposes a `Config` struct and a `New(Config) theauth.Provider` constructor.

## Multiple providers at once

```go
a, _ := theauth.New(theauth.Config{
    Storage: store,
    BaseURL: "https://myapp.com",
    Providers: []theauth.Provider{
        github.New(github.Config{
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        }),
        google.New(google.Config{
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        }),
    },
})
```

See [`examples/oauth-multi-provider/`](https://github.com/glincker/theauth-go/tree/main/examples/oauth-multi-provider) for a full runnable example.

## Endpoints

When providers are configured, `a.Mount(r)` adds:

```
GET /auth/providers/{name}/start    -- redirect to provider
GET /auth/providers/{name}/callback -- consume code, issue session
```

Where `{name}` is `github`, `google`, `microsoft`, or `discord`.

## Provider tokens

Provider access tokens are encrypted with AES-256-GCM before storage. The `Config.EncryptionKey` (32-byte) is required if you want provider token storage. Without it, the OAuth state is stored as-is and provider tokens are not persisted.

## Custom provider

Implement the `theauth.Provider` interface:

```go
type Provider interface {
    Name() string
    AuthURL(state, redirectURI string) string
    ExchangeCode(ctx context.Context, code, redirectURI string) (ProviderToken, error)
    UserInfo(ctx context.Context, token ProviderToken) (ProviderUser, error)
}
```

Pass your implementation to `Config.Providers` alongside the built-in providers.

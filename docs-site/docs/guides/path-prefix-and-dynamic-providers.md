# Custom Path Prefix and Dynamic Providers

Two options for apps that already own their public URLs: serve the library under
a prefix of your choosing, and let OAuth/OIDC providers change at runtime.

## Path prefix

`Config.PathPrefix` sets where `Mount` and `Handler` serve the auth routes. The
default is `/auth`, so existing apps are unchanged.

```go
a, err := theauth.New(theauth.Config{
    Storage:    store,
    BaseURL:    "https://app.example.com",
    PathPrefix: "/api/v1/auth",
})
mux.Handle("/", a.Handler()) // no http.StripPrefix needed
```

The prefix must start with `/`, must not end with `/`, and must not contain a
query, fragment, wildcard, whitespace or empty/dot segments. Anything else makes
`New` return an error.

Every URL the library generates follows the prefix:

| Generated value | Example with `/api/v1/auth` |
| --- | --- |
| OAuth redirect URI | `https://app.example.com/api/v1/auth/providers/github/callback` |
| Magic link | `https://app.example.com/api/v1/auth/magic-link/verify?token=...` |
| Password reset link | `https://app.example.com/api/v1/auth/email-password/reset?token=...` |
| WebAuthn challenge cookie `Path` | `/api/v1/auth/webauthn` |
| Authorization server default `LoginURL` | `/api/v1/auth/login` |

Register the redirect URI shown above at each identity provider. Routes outside
the prefix (`/oauth/*`, `/.well-known/*`, `/scim/v2/*`, `/admin/v1/*`) keep their
own paths. The device verification page stays at `BaseURL + "/device"` unless
`DeviceConfig.VerificationURI` is set.

### clientauth

`clientauth.DeviceOptions.AuthPath` and `clientauth.Client.AuthPath` take the same
prefix. They default to `clientauth.DefaultAuthPath` (`/auth`).

```go
clientauth.DeviceLogin(ctx, clientauth.DeviceOptions{
    ServerURL: "https://app.example.com",
    AuthPath:  "/api/v1/auth",
})
```

## Dynamic providers

`Config.ProviderResolver` supplies providers that are not known at startup.

```go
type ProviderResolver interface {
    Resolve(ctx context.Context, name string) (Provider, bool, error)
}
```

Return `(nil, false, nil)` for an unknown name. A resolver may also implement
`List(ctx) ([]Provider, error)`, which `(*TheAuth).ListProviders` includes.

```go
a, err := theauth.New(theauth.Config{
    // ...
    EncryptionKey:       key,            // required with a resolver
    ProviderResolver:    dbResolver,
    ProviderResolverTTL: 30 * time.Second,
})

// After an admin edits or removes a provider:
a.InvalidateProvider("corp-sso")
```

Behavior:

- Static `Providers` win. Set `ProviderResolverFirst` to consult the resolver
  first, falling back to static providers when it reports not found.
- Names must match `^[a-z0-9][a-z0-9_-]{0,62}$` before they reach the resolver.
  Other names get a 404.
- A resolver error fails the flow closed (503 on start, no fallback, not cached).
- The returned provider's `Name()` must equal the requested name.
- `ProviderResolverTTL` caches answers, including "not found". Zero disables
  caching. `InvalidateProvider` drops one entry immediately and also discards any
  lookup that was in flight.
- State, PKCE, nonce and browser binding are unchanged. A provider removed
  between start and callback fails the callback.

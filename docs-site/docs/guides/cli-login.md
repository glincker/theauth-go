# CLI Login

The `clientauth` package lets any Go CLI sign in to a theauth-go server with the RFC 8628 device grant. It depends on the standard library only.

## Server side

Enable API tokens with a `Device` block, as described in [API Tokens and Device Login](api-tokens.md). The CLI talks to `/auth/device/code` and `/auth/device/token`.

## Login

```go
store, _ := clientauth.NewFileStore("mycli") // os.UserConfigDir()/mycli/credentials.json
cred, err := clientauth.DeviceLogin(ctx, clientauth.DeviceOptions{
    ServerURL:   "https://auth.example.com",
    ClientName:  "mycli",
    Scopes:      []string{"read", "deploy"},
    Store:       store,
    OpenBrowser: openBrowser, // optional
})
```

`DeviceLogin` requests a code, shows the verification URI and user code (to stderr by default, or through `Prompt`), optionally opens the browser, and polls. It honors the server's interval, adds 5 seconds on `slow_down` (and on HTTP 429), and returns `ErrAccessDenied` or `ErrDeviceExpired` for a refused or timed out request. Pass `Sleep` and `Now` to control time in tests.

## Calling the server

```go
client, _ := clientauth.NewClient("https://auth.example.com", store)
req, _ := client.NewRequest(ctx, http.MethodGet, "/api/things", nil)
resp, err := client.Do(req)
if errors.Is(err, clientauth.ErrReloginRequired) { /* run login again */ }
```

`Do` attaches the bearer token and returns `ErrReloginRequired` when the token is expired locally or the server answers 401. It returns `ErrNotLoggedIn` when nothing is stored, and refuses requests to any other origin so the token cannot leak.

## Storage

- `FileStore`: one 0600 file in a 0700 directory, one entry per server URL, atomic replace, and a lock file so concurrent processes do not drop each other's entries.
- `KeychainStore`: wraps a `KeychainBackend` you supply. The `Get`, `Set` and `Delete` functions of `github.com/zalando/go-keyring` fit with a thin adapter, so the package itself needs no cgo.
- Any other backend implements the three-method `TokenStore` interface.

## Whoami and Logout

`Client.Whoami` and `Client.Logout` call a bearer-authenticated route (`/auth/tokens/current` by default, change it with `Client.SelfPath`), then `Logout` deletes the local credential even if revocation fails.

!!! note
    The server shipped in this version authenticates `DELETE /auth/tokens/{id}` with a session cookie only, and does not expose the minted token ID to the device client, so a bearer token cannot yet revoke or describe itself. Until the server adds a self-service route, `Logout` clears the local credential and returns the server error.

A complete CLI is in `examples/cli-login`.

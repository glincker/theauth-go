# theauth-go adapter for Echo v4

Native Echo v4 middleware, accessors and a mount helper for
[theauth-go](https://github.com/glincker/theauth-go). Separate module so the
root module does not depend on Echo v4.

```
go get github.com/glincker/theauth-go/adapters/echo
```

```go
a, _ := theauth.New(theauth.Config{Storage: store, BaseURL: "https://app.example.com"})
e := echo.New()
theauthecho.Mount(a, e, "/api")
e.GET("/me", func(c echo.Context) error {
    u, _ := theauthecho.User(c)
    return c.JSON(200, map[string]string{"email": u.Email})
}, theauthecho.RequireAuth(a))
```

| Function | Purpose |
| --- | --- |
| `Authn(a)` | Attach the user and session when a valid cookie is present; never rejects |
| `RequireAuth(a)` | 401 unless the session is fully authenticated |
| `RequireAbility(a, "deploy")` | Session or API bearer token holding the ability (needs `Config.APITokens`) |
| `User(c)`, `Session(c)`, `Principal(c)` | Accessors for the values the middleware attached |
| `Mount(a, router, "/api")` | Serve every theauth route under a prefix (`/api/auth/signin`); an empty prefix mounts `/auth`, `/oauth` and `/.well-known` |

## Errors

The adapter writes no error bodies. 401 and 403 responses come from theauth
and go through `theauth.Config.ErrorResponder` when you set it, so one
responder shapes errors for every framework. With it unset the bytes are the
default `application/problem+json` bodies.

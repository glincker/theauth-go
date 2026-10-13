# theauth-go adapter for Fiber v2

Native Fiber v2 middleware, accessors and a mount helper for
[theauth-go](https://github.com/glincker/theauth-go). Separate module so the
root module does not depend on Fiber v2.

```
go get github.com/glincker/theauth-go/adapters/fiber
```

```go
a, _ := theauth.New(theauth.Config{Storage: store, BaseURL: "https://app.example.com"})
app := fiber.New()
theauthfiber.Mount(a, app, "/api")
app.Get("/me", theauthfiber.RequireAuth(a), func(c *fiber.Ctx) error {
    u, _ := theauthfiber.User(c)
    return c.JSON(fiber.Map{"email": u.Email})
})
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

## Streaming caveat

Fiber runs on fasthttp. The adaptor runs theauth's net/http handlers against an
in-memory response writer and copies the result, so responses from `Mount` and
from the theauth middleware are fully buffered. `http.Flusher` streaming (SSE,
long polling) is unavailable through them. Keep streaming routes as plain Fiber
handlers and put only `Authn`, `RequireAuth` or `RequireAbility` in front.

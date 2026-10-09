# theauth-go CLI and OpenAPI

```
go install github.com/glincker/theauth-go/v2/cmd/theauth-go@latest
```

| Command | Purpose |
|---|---|
| `theauth-go secret` | Print random key material. Flags: `--bytes` (16 to 128, default 32), `--format base64url\|hex\|env`, `--name` for the env format |
| `theauth-go openapi` | Print an OpenAPI 3.1 document for the default route set. Flags: `--base-url`, `--title`, `--version`, `--out` |

Related binaries: `theauth-doctor` fetches the security report of a running server, and `theauth-migrate` imports users from Auth0 and Cognito.

## Generating OpenAPI from your own router

The CLI documents the default routes. To describe the routes your application actually mounts (optional features included), call the library from your own code:

```go
r := chi.NewRouter()
auth.Mount(r)

doc, err := openapi.Generate(r, openapi.Info{
	Title:     "My API",
	Version:   "1.0.0",
	ServerURL: "https://auth.example.com",
})
```

Routes are read with `chi.Walk`, so the document cannot drift from what is mounted. Well-known auth routes get summaries, tags and security requirements (session cookie or bearer). Other routes are listed with a generated summary and operation id. Request and response bodies are described as generic objects; the document is meant for client discovery and gateways, not for full schema generation.

# MCP interop tests

Runs the official Go MCP SDK (`github.com/modelcontextprotocol/go-sdk` v1.8.0) as a client against a theauth-go authorization server and an MCP server protected by `mcpresource`. This is a separate Go module, so the root `go.mod`, `go.sum` and `go test ./...` are unaffected.

```
cd integration/mcp-interop
GOWORK=off go test -count=1 ./...
```

## What it proves

- The AS serves RFC 8414 metadata and the resource server serves RFC 9728 protected resource metadata that the SDK client accepts.
- An unauthenticated call gets a 401 whose `WWW-Authenticate` carries the `resource_metadata` pointer.
- The SDK's `AuthorizationCodeHandler` completes the whole flow unmodified: discovery, RFC 7591 dynamic client registration, authorization code with PKCE S256 and the RFC 8707 `resource` parameter, RFC 9207 `iss` handling, token exchange, then an authenticated `tools/call` over the streamable HTTP transport. The tool sees the user as the token subject with the granted scope.

## What it does not prove

- The browser is simulated: the authorization-code fetcher calls `/oauth/authorize` with a pre-made session cookie. Login and consent UI are not exercised.
- Token validation uses JWKS only. Introspection, revocation, DPoP and refresh are not covered here.
- Servers run on `httptest` TLS listeners with in-memory storage. No other SDK is covered yet: `mark3labs/mcp-go` is not included.
- Only one SDK version is pinned, so it detects drift only when the pin is bumped.

## Demo

`go run ./cmd/demo` runs the official go-sdk client against a theauth-go authorization server and prints each HTTP request it makes. The recording at `.github/demo/mcp-auth.gif` is rendered from `.github/demo/mcp-auth.tape` with [VHS](https://github.com/charmbracelet/vhs). Login and consent are simulated here too.

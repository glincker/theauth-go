# mcp-server

A small MCP resource server built on the separate `mcpresource` module. One middleware line validates RFC 9068 access tokens, walks RFC 8693 actor chains, and serves RFC 9728 metadata pointers. `GET /tools` echoes the resolved principal.

## Run

```bash
MCP_RESOURCE=https://mcp.example.com \
MCP_JWKS_URI=https://as.example.com/oauth/jwks \
MCP_INTROSPECT_URI=https://as.example.com/oauth/introspect \
MCP_CLIENT_ID=mcp-resource-client \
MCP_CLIENT_SECRET=change-me \
go run .
```

It listens on `:8090` (override with `MCP_LISTEN_ADDR`). Startup logs any `mcpresource` diagnostics, such as a missing JWKS endpoint. Point the three URIs at an authorization server built with theauth-go (`Config.AuthorizationServer`).

See [Resource server (mcpresource)](https://docs.theauth.dev/go/concepts/resource-server) and [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization).

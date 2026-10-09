# Discovery URLs with path components

MCP clients find your servers through two well-known documents. Both specs say the `/.well-known/` segment goes between the host and the path, not at the end.

## Protected resource metadata (RFC 9728)

For a resource identifier of `https://mcp.example.com/api/mcp`, the metadata lives at:

```
https://mcp.example.com/.well-known/oauth-protected-resource/api/mcp
```

A resource with no path (or just `/`) uses the bare `/.well-known/oauth-protected-resource`. A query component stays after the inserted path.

`mcpresource` puts this URL in the `resource_metadata` parameter of every `WWW-Authenticate` challenge. The authorization server answers the path form by matching the suffix against the path of each configured resource, so a resource on a different origin than the issuer works too. A trailing slash on the request is ignored.

## Authorization server metadata (RFC 8414)

If the issuer is `https://auth.example.com/tenant1`, clients fetch:

```
https://auth.example.com/.well-known/oauth-authorization-server/tenant1
https://auth.example.com/.well-known/openid-configuration/tenant1
```

Both are served, along with the plain forms. A suffix that does not equal the issuer path returns 404, so one origin never answers for an issuer it does not own. The `openid-configuration` routes return the same document as the OAuth metadata route.

## Clock skew and JWKS errors in mcpresource

`WithClockSkew` sets the tolerance for `exp`, `nbf` and `iat` (default 60 seconds):

```go
v := mcpresource.New("https://mcp.example.com/api/mcp",
	mcpresource.WithJWKS("https://auth.example.com/oauth/jwks"),
	mcpresource.WithClockSkew(2*time.Minute),
)
http.Handle("/api/mcp", v.Middleware(handler))
```

If a fetched JWKS holds no usable Ed25519 key (every entry malformed, or the set is empty), the fetch now fails with an error that counts the bad entries. The previous key set stays in use instead of being replaced by an empty one.

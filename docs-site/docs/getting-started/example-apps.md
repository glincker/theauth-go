# Example Apps

The repository ships eight runnable example applications. Each example has a `README`, single-file `main.go`, `go.mod`, `docker-compose.yml`, `.env.example`, and `Makefile`.

| Example | What it shows |
|---|---|
| [`examples/chi-app/`](https://github.com/glincker/theauth-go/tree/main/examples/chi-app) | Magic links and email/password with chi |
| [`examples/gin-app/`](https://github.com/glincker/theauth-go/tree/main/examples/gin-app) | Drop-in with Gin |
| [`examples/echo-app/`](https://github.com/glincker/theauth-go/tree/main/examples/echo-app) | Drop-in with Echo |
| [`examples/stdlib-app/`](https://github.com/glincker/theauth-go/tree/main/examples/stdlib-app) | Pure `net/http`, no framework |
| [`examples/oauth-multi-provider/`](https://github.com/glincker/theauth-go/tree/main/examples/oauth-multi-provider) | GitHub + Google + Microsoft + Discord in one app |
| [`examples/webauthn-passkey/`](https://github.com/glincker/theauth-go/tree/main/examples/webauthn-passkey) | Passkey register and discoverable login |
| [`examples/totp-stepup/`](https://github.com/glincker/theauth-go/tree/main/examples/totp-stepup) | Password + TOTP step-up flow |
| [`examples/mcp-server/`](https://github.com/glincker/theauth-go/tree/main/examples/mcp-server) | MCP resource server using `mcpresource` middleware |

## Running an example

```bash
git clone https://github.com/glincker/theauth-go
cd theauth-go/examples/chi-app
cp .env.example .env
docker-compose up -d  # starts Postgres
make run
```

The chi-app listens on `:8080` by default. Check its `README` for the environment variables it reads.

## MCP server example

The `examples/mcp-server` example is the shortest demonstration of the `mcpresource` middleware on a chi server. It shows the one-import claim: middleware wiring plus principal extraction in roughly ten lines of Go. See [Resource Server (mcpresource)](../concepts/resource-server.md) for the walkthrough.

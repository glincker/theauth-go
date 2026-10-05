# Single binary with SQLite

A complete app with auth in one static Go binary and one SQLite file: no database server, no cgo, no framework.

- `storage/sqlite` (pure Go, `modernc.org/sqlite`) holds users, sessions and tokens.
- Stdlib `net/http` mux: `/auth/` is `a.Handler()`.
- First-run setup token: the first admin can only sign up with the token, then signup closes.
- `GET /api/whoami` is guarded by `RequireAbility("read")` and accepts a session cookie or a bearer token.
- Scoped API tokens are minted through the built-in `POST /auth/tokens`.
- `cmd/mycli` signs in with the RFC 8628 device grant (`clientauth.DeviceLogin`), then calls `Whoami`, `Logout` and the API.
- `GET /device` is a tiny approval page for the device flow.

## Requirements

Go 1.26 or newer. `storage/sqlite` and its `modernc.org/sqlite` dependency declare `go 1.26.0`, so this example does too. The root `theauth-go` module still builds on Go 1.25.

## Run

```sh
cd examples/single-binary-sqlite
SETUP_TOKEN=change-me go run .
```

Without `SETUP_TOKEN` a random one is generated and logged once at startup. Environment: `BASE_URL` (default `http://localhost:8080`), `ADDR` (`:8080`), `DB_PATH` (`app.db`).

Create the first admin, mint a token, call the API:

```sh
curl -c jar -X POST localhost:8080/auth/email-password/signup \
  -H 'X-Setup-Token: change-me' -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"correct horse battery staple"}'

curl -b jar -X POST localhost:8080/auth/tokens -H 'Content-Type: application/json' \
  -d '{"name":"ci","abilities":["read"]}'          # prints the token once

curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/whoami
```

Sign a CLI in with the device grant:

```sh
go build -o mycli ./cmd/mycli
export MYCLI_SERVER=http://localhost:8080
./mycli login      # prints a code; approve it at http://localhost:8080/device
./mycli whoami
./mycli get /api/whoami
./mycli logout     # revokes the token server side and deletes it locally
```

Signup, signin and token routes share a per-IP budget of 5 requests a minute by default (`Config.RateLimitPerIP`).

## Smoke test

```sh
go vet ./... && go test ./...
```

`TestSmoke` boots the server on a random port with a temporary SQLite file and checks, over real HTTP:

1. signup without the setup token is refused, with it the first admin is created, a second signup is closed;
2. `/api/whoami` is 401 anonymously and 200 with a freshly minted token;
3. it builds `mycli`, runs `mycli login` headlessly, approves the printed code as the signed-in admin, then runs `whoami`, `get /api/whoami` and `logout`, and checks the API call fails after logout.

CI note: this module needs Go 1.26, so run it in a job that uses that toolchain, separate from the root module jobs that run on 1.25.

## Production notes

- Serve over HTTPS and set `BASE_URL` to the https origin: the session cookie is then `Secure`.
- Put the database on local disk. One process owns the file; WAL mode and a busy timeout are set in the DSN.
- Call `store.SweepExpired` on a ticker to delete expired rows (see the SQLite storage guide).
- Replace `UserAbilities` in `server.go` with your own role model.

# theauth-go gin example

## What this shows

theauth-go drops into a Gin router by mounting its handlers onto a chi
subrouter, then wrapping the result with `gin.WrapH`. The same pattern
works for any third-party router that accepts an `http.Handler`.

## Prerequisites

- Go 1.25 or newer.
- Docker (only if you want the Postgres backed variant; in-memory is the
  default).

## Setup

```
cp .env.example .env
make up      # optional: starts Postgres on port 5433
```

## Run

```
make run
```

Server listens on `:8081`. The auth routes mount under `/auth/`.

## Try it

```
# request a magic link (noop sender prints the URL to your terminal)
curl -X POST http://localhost:8081/auth/magic-link \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@example.com"}'

# paste the verify URL from the server logs into your browser.

# check the authenticated user (cookie set by the verify endpoint)
curl --cookie-jar c.txt --cookie c.txt http://localhost:8081/me
```

## Teardown

```
make down
```

## Troubleshooting

- Port 8081 already in use: set `ADDR=:8090` in `.env` and re-run.
- `BASE_URL` mismatch on OAuth callback: the magic link URL embedded in
  the email points at `BASE_URL`, which must match what your browser
  sees.
- Postgres up but `DATABASE_URL` not set: the example only uses the
  in-memory store. Wire Postgres yourself by importing
  `github.com/glincker/theauth-go/storage/postgres` and swapping the
  storage adapter in `main.go`.

# theauth-go echo example

## What this shows

theauth-go plugs into Echo v4 by mounting its handlers onto a chi
subrouter and wrapping the result with `echo.WrapHandler`. Same pattern
as the gin example.

## Prerequisites

- Go 1.25 or newer.
- Docker (only if you want the Postgres backed variant).

## Setup

```
cp .env.example .env
make up      # optional: starts Postgres on port 5434
```

## Run

```
make run
```

Server listens on `:8082`. The auth routes mount under `/auth/`.

## Try it

```
curl -X POST http://localhost:8082/auth/magic-link \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@example.com"}'

# paste the verify URL from the server logs into your browser, then:
curl --cookie-jar c.txt --cookie c.txt http://localhost:8082/me
```

## Teardown

```
make down
```

## Troubleshooting

- Port 8082 already in use: set `ADDR=:8090` in `.env`.
- `BASE_URL` mismatch: the magic link URL embedded in the noop email
  points at `BASE_URL`. It must match what your browser sees.
- Postgres up but `DATABASE_URL` not set: this example uses the
  in-memory store only. Swap the storage adapter in `main.go` to use
  Postgres.

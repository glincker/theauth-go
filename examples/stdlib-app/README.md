# theauth-go stdlib example

## What this shows

theauth-go runs behind a plain `net/http.ServeMux` with Go 1.22+
pattern routing. Chi is only used to provide the `chi.Router` value
that `theauth.TheAuth.Mount` expects; the rest of the server is
framework-free. Proves the library is router agnostic.

## Prerequisites

- Go 1.25 or newer.
- Docker (only if you want the Postgres backed variant).

## Setup

```
cp .env.example .env
make up      # optional: starts Postgres on port 5435
```

## Run

```
make run
```

Server listens on `:8083`.

## Try it

```
curl -X POST http://localhost:8083/auth/magic-link \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@example.com"}'

# paste the verify URL from the server logs into your browser, then:
curl --cookie-jar c.txt --cookie c.txt http://localhost:8083/me
```

## Teardown

```
make down
```

## Troubleshooting

- Port 8083 already in use: set `ADDR=:8090` in `.env`.
- `BASE_URL` mismatch: the magic link URL embedded in the noop email
  points at `BASE_URL`. It must match what your browser sees.
- Postgres up but `DATABASE_URL` not set: this example uses in-memory
  only. Wire Postgres yourself in `main.go`.

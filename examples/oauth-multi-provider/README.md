# theauth-go OAuth multi provider example

## What this shows

A single TheAuth instance wired up with all four OAuth providers
shipped by the library: GitHub, Google, Microsoft, and Discord. The
landing page renders four sign in buttons; pick one and you walk
through the standard OAuth code plus PKCE flow ending at `/me` with a
session cookie.

## Prerequisites

- Go 1.25 or newer.
- Docker (only if you want the Postgres backed variant).
- OAuth client credentials for each provider you want to test. You can
  enable only a subset by leaving the others blank: those buttons will
  404 cleanly.

## Setup

```
cp .env.example .env
# fill in the CLIENT_ID / CLIENT_SECRET pairs you have
make up      # optional Postgres on port 5436
```

Set the OAuth redirect URI on each provider's developer console to the
matching callback URL:

- GitHub: `http://localhost:8084/auth/providers/github/callback`
- Google: `http://localhost:8084/auth/providers/google/callback`
- Microsoft: `http://localhost:8084/auth/providers/microsoft/callback`
- Discord: `http://localhost:8084/auth/providers/discord/callback`

## Run

```
make run
```

Open `http://localhost:8084/` in your browser.

## Try it

1. Click any provider button.
2. Approve the consent screen on the provider's site.
3. The provider redirects back to `/auth/providers/<name>/callback`,
   which sets a session cookie and 302s to `/me`.
4. `/me` prints the email address of the signed in user.

## Teardown

```
make down
```

## Troubleshooting

- "unknown provider" 404 when clicking a button: the corresponding
  CLIENT_ID and CLIENT_SECRET are not set in `.env`.
- "state mismatch" 400 on callback: the magic state cookie expired or
  was blocked. Most browsers respect SameSite=Lax for localhost; if you
  are behind a proxy that strips cookies, set up a proper hostname.
- "OAuth callback failed" 400: the provider rejected the code exchange,
  usually because the redirect URI registered on its console does not
  match the one this example sends. Double check the URLs in the Setup
  section.

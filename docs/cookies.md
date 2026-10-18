# Cookies and response headers

Every cookie the library writes goes through one builder in `internal/httpsec`: the session cookie, the cleared session cookie on sign out, the trusted-device cookie, the OAuth state cookie and the WebAuthn challenge cookie. `Config.Cookies` tunes the attributes for all of them at once. The zero value keeps the historic behavior.

## Defaults

| Attribute | Value |
|---|---|
| Name | `theauth_session` (`Config.CookieName`) |
| `HttpOnly` | always on, not configurable |
| `Secure` | on when `Config.SecureCookie` is true or `BaseURL` is https. Otherwise added per request on TLS or on `X-Forwarded-Proto: https` from a `TrustedProxies` address |
| `SameSite` | `Lax` |
| `Path` | `/` (the WebAuthn challenge cookie is scoped to `<PathPrefix>/webauthn`) |
| `Domain` | unset (host-only) |
| `Partitioned` | off |
| `Expires` and `Max-Age` | both set, from `Config.SessionTTL` |

## Config.Cookies

| Field | Values | Meaning |
|---|---|---|
| `Domain` | host name, for example `example.com` | Share the cookies with every subdomain. Empty keeps them host-only. Cannot be combined with `Prefix: "host"`. |
| `SameSite` | `lax` (default), `strict`, `none` | `none` requires Secure. `strict` is not applied to the OAuth state cookie, which stays Lax because the provider callback is a cross-site navigation. |
| `Partitioned` | bool | Adds the CHIPS `Partitioned` attribute. Requires Secure. |
| `Prefix` | empty, `secure`, `host` | Prepends `__Secure-` or `__Host-` to the session cookie name. A `CookieName` that already has the prefix is kept. |

`SecurityHeaders` is a separate `Config` bool, see below.

## Validation

`New` returns an error, and the doctor never has to find it at request time, for these combinations:

- `__Host-` name that is not Secure, or has `Domain` set (the session cookie is always Path=/).
- `__Secure-` name that is not Secure.
- `SameSite: "none"` without Secure.
- `Partitioned` without Secure.
- `Prefix` that conflicts with a `CookieName` already carrying the other prefix.
- A `Domain` that is not a bare host name.

"Secure" here means the static setting (`SecureCookie` true or an https `BaseURL`). The per-request upgrade on TLS does not count, because the same cookie must be valid on every request.

Cleared cookies repeat `Domain`, `Path`, `Secure` and `Partitioned` with `Max-Age=0`, so browsers delete the stored cookie, and a cleared `__Host-` cookie stays valid for the browser.

## Behavior change in this release

Cookies now carry `Max-Age` in addition to `Expires`. Nothing else changes with the zero-value config.

## Response headers

- Auth routes (everything under `Config.PathPrefix`, default `/auth`) send `Cache-Control: no-store`, so `/auth/me`, sign in, sign up and the session list never sit in a browser or proxy cache. A handler that sets its own `Cache-Control` wins.
- `Config.SecurityHeaders: true` (default off) adds `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and, on https requests only, `Strict-Transport-Security: max-age=31536000; includeSubDomains`. The doctor reports `headers.security_off_https` while it is off on an https `BaseURL`.

## Doctor findings

`cookie.domain_no_prefix`, `cookie.samesite_none_unpartitioned`, `headers.security_off_https`, and the existing `cookie.insecure_http` for Secure disabled outside localhost. See `SECURITY-DOCTOR.md`.

## TypeScript parity

The TypeScript SDK (`sdk/docs/cookies.mdx`, `packages/core/src/session/cookie.ts`) has `domain`, `sameSite`, `partitioned` and the same `__Host-` and `__Secure-` checks, which throw when the options are invalid. Go matches those rules and adds one: the check runs in `New`, not on the first response. Differences: Go has no per-cookie override (one policy covers all cookies), the Go prefix is a mode (`Prefix`) applied to the session cookie, and Go decides Secure from `SecureCookie`, `BaseURL`, TLS and trusted proxies instead of `NODE_ENV`.

Cookie consent banners are out of scope for an auth core in both libraries.

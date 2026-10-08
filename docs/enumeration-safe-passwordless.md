# Enumeration-safe passwordless flows

An attacker who can tell registered emails from unregistered ones can build a target list, so the endpoints that take an email and send a link answer every address the same way.

## What is covered

| Endpoint | Known email | Unknown email |
| --- | --- | --- |
| `POST /auth/magic-link` | `200 {"sent":true}` | `200 {"sent":true}` |
| `POST /auth/email-password/forgot` | `200 {"sent":true}` | `200 {"sent":true}` |

Status, body and content type are identical. The per-IP and per-email rate limits apply to the address as typed, whether or not it is registered, so a `429` says nothing about the account.

## Timing

`/forgot` used to look the user up, mint a token and send the email before answering, while an unknown address answered right away. That gap was measurable. The lookup still happens inline, but token creation and the email send now run in the background with a detached context and a 30 second limit. Both branches return after one storage lookup. A delivery failure is logged and does not change the response.

`/magic-link` creates a link and sends mail for any address, so both branches already did the same work. Signing in uses the existing dummy Argon2id verify for unknown users.

## Try it

```go
a, _ := theauth.New(theauth.Config{ /* storage, sender, signing key */ })
r := chi.NewRouter()
a.Mount(r)

// Both calls return 200 {"sent":true}, registered or not:
//   curl -X POST localhost:8080/auth/email-password/forgot \
//        -d '{"email":"nobody@example.com"}'
```

## What is not covered

`POST /auth/email-password/signup` still answers `409 email_taken` for a registered address. Signup returns a session immediately, so hiding the conflict would need an email-confirmation step first. If account enumeration through signup matters to you, put signup behind the magic-link flow or a bootstrap setup token.

Magic-link consumption creates a user the first time an unknown email completes a link. That is unchanged and does not affect the request response.

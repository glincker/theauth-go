# webauthn-passkey

Passkey registration and discoverable login with `Config.WebAuthn`. A single page registers a passkey and then signs in with it.

## Run

```bash
go run .
```

Open <http://localhost:8080>. Browsers only allow WebAuthn on `localhost` or an HTTPS origin, so for any other host put a TLS proxy in front (mkcert works) and set the matching values:

| Variable | Default | Meaning |
|---|---|---|
| `RPID` | `localhost` | Relying party ID, the registrable domain |
| `ORIGIN` | `http://localhost:8080` | Exact origin the browser uses |

Storage is in memory. The example skips cookie, CSRF and cross-origin SPA setup to keep the file short.

See the [passkeys guide](https://docs.theauth.dev/go/guides/webauthn-passkeys).

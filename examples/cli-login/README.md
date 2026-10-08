# cli-login

A host CLI that authenticates against a theauth-go server with RFC 8628 device login, using the `clientauth` package. Credentials are kept in a file store under the app name `mycli`.

## Run

```bash
MYCLI_SERVER=https://auth.example.com go run . login
MYCLI_SERVER=https://auth.example.com go run . whoami
MYCLI_SERVER=https://auth.example.com go run . get /api/things
MYCLI_SERVER=https://auth.example.com go run . logout
```

The server must run theauth-go with `Config.APITokens`. See [CLI login](https://docs.theauth.dev/go/guides/cli-login).

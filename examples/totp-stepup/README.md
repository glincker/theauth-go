# totp-stepup

Password sign-in with a TOTP second factor. A single page signs up, enrolls TOTP, signs out, signs back in (the session is pending a second factor), then posts the current six-digit code to `/auth/totp/verify` to upgrade the session.

## Run

```bash
go run .
```

Open <http://localhost:8080>. Storage is in memory. `ENCRYPTION_KEY` (32 bytes) protects TOTP secrets at rest; the default in `main.go` is for local use only, so set your own for anything else. `BASE_URL` overrides the origin.

The page shows the `otpauth://` URI and the base32 secret instead of a QR code. Enter the secret into an authenticator app, or render the URI with any QR library, since QR generation is outside this library's scope.

See the [TOTP guide](https://docs.theauth.dev/go/guides/totp).

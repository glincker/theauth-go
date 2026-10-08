# oauth-apple

Sign in with Apple using the `provider/apple` package. Apple uses a signed ES256 JWT as the client secret instead of a static string, and sends the callback as a form POST (`response_mode=form_post`). State is held in memory.

## Run

```bash
APPLE_TEAM_ID=A1B2C3D4E5 \
APPLE_KEY_ID=ABCDE12345 \
APPLE_BUNDLE_ID=com.example.app.signin \
APPLE_KEY_FILE=/path/to/AuthKey_ABCDE12345.p8 \
go run .
```

Open <http://localhost:8092> and click the sign-in link.

## Setup

From the Apple Developer console you need a Team ID, a Key ID, a Services ID and the `.p8` private key (Apple lets you download it once). Configure Sign In with Apple on the Services ID with this redirect URL:

```
http://localhost:8092/auth/providers/apple/callback
```

Apple requires HTTPS outside of production-like setups, so use a tunnel such as ngrok for local testing and set `BASE_URL` to the tunnel origin.

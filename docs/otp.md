# One-time codes (email and SMS)

The `otp` package issues short numeric codes, sends them through a `Sender` you choose, and verifies them with a resend cooldown, an attempt limit and a lockout window. It proves control of an email address or phone number. It does not create sessions: when `Verify` returns nil, continue with your own sign-in or verification step.

State lives in a `kv.Cache`, so it works with the in-memory store, the SQL adapters or Redis (see [pluggable stores](pluggable-stores.md)). Use a shared cache when you run more than one replica.

```go
package main

import (
	"context"
	"errors"
	"log"

	"github.com/glincker/theauth-go/v2/email"
	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/otp"
)

func main() {
	ctx := context.Background()
	secret := []byte("replace-with-32-or-more-random-bytes")

	emailOTP, err := otp.New(otp.Config{
		Channel: otp.ChannelEmail,
		Cache:   kv.NewMemory(),
		Sender:  otp.EmailSender{Mailer: email.Noop{}},
		Secret:  secret,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := emailOTP.Issue(ctx, "login", "ann@example.com"); err != nil {
		log.Fatal(err)
	}
	err = emailOTP.Verify(ctx, "login", "ann@example.com", "123456")
	switch {
	case errors.Is(err, otp.ErrInvalid):
		// wrong or expired code
	case errors.Is(err, otp.ErrLocked):
		// too many wrong guesses
	}
}
```

Generate the secret with `theauth-go secret`.

## SMS

```go
smsOTP, _ := otp.New(otp.Config{
	Channel: otp.ChannelSMS,
	Cache:   cache,
	Secret:  secret,
	Length:  6,
	Sender: otp.TwilioSender{
		AccountSID: os.Getenv("TWILIO_SID"),
		AuthToken:  os.Getenv("TWILIO_TOKEN"),
		From:       os.Getenv("TWILIO_FROM"),
	},
})
```

Phone numbers are normalized by removing spaces, dashes and parentheses. Send numbers in E.164 form (`+15550100000`) so the same number always maps to the same record.

## Custom senders

`Sender` has one method. Use `otp.SenderFunc` for a quick adapter around any provider (Vonage, SNS, a queue):

```go
sender := otp.SenderFunc(func(ctx context.Context, m otp.Message) error {
	return myProvider.Text(ctx, m.To, "Your code is "+m.Code)
})
```

## Behavior

| Setting | Default | Notes |
|---|---|---|
| `Length` | 6 | 4 to 10 digits, drawn with rejection sampling (no modulo bias) |
| `TTL` | 10 minutes | Code lifetime |
| `Cooldown` | 60 seconds | `Issue` returns `ErrCooldown` inside the window; a failed send releases it |
| `MaxAttempts` | 5 | Counted per destination and purpose; the next guess locks it |
| `LockoutDuration` | 15 minutes | `Issue` and `Verify` return `ErrLocked` while it lasts |

Security notes:

- Codes are stored as an HMAC under `Secret`, never in clear text. Cache keys are derived from the destination, so addresses and numbers do not appear in the cache.
- Comparison is constant time, and an unknown code costs the same as a wrong one. Wrong, expired and unknown codes all return `ErrInvalid`.
- A successful `Verify` consumes the code. Issuing a new code resets the attempt counter.
- `Purpose` separates flows. A code issued for `login` does not verify for `reset`.
- Rate limit the HTTP endpoint that calls `Issue` by IP as well (`RateLimitByIP`), since the cooldown is per destination.

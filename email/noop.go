package email

import (
	"context"
	"log/slog"
)

// Noop is a Sender that logs the email and returns nil.
// Use as the default when no SMTP sender is configured so the library
// runs out-of-the-box in development.
type Noop struct{}

func (Noop) Send(_ context.Context, to, subject, body string) error {
	slog.Info("theauth/email: noop send", "to", to, "subject", subject, "body", body)
	return nil
}

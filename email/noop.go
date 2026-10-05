package email

import (
	"context"
	"log/slog"

	"github.com/glincker/theauth-go/v2/internal/emailnorm"
)

// Noop is a Sender that logs the email and returns nil.
// Use as the default when no SMTP sender is configured so the library
// runs out-of-the-box in development.
type Noop struct{}

// SECURITY: this sender logs the full email body including any magic-link tokens. NEVER use Noop in production.
// The recipient address itself is logged only as a short hash.
func (Noop) Send(_ context.Context, to, subject, body string) error {
	slog.Info("theauth/email: noop send", "to_ref", emailnorm.LogRef(to), "subject", subject, "body", body)
	return nil
}

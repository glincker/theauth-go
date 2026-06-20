package email

import "context"

// Sender delivers a single email. Implementations should be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

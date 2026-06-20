package theauth

import "context"

type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
)

// UserFromContext returns the authenticated User attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// SessionFromContext returns the Session attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey).(*Session)
	return s, ok
}

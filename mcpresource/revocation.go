package mcpresource

import (
	"context"
	"errors"
	"net/http"
)

// RevocationChecker is consulted for a token that already passed offline
// validation (signature, audience, expiry, DPoP binding). It lets a resource
// server that validates JWTs locally see revocations that would otherwise
// stay invisible until exp, which matters most for device tokens. The default
// is no checker.
//
// IsRevoked must be safe for concurrent use. Keep it fast or cache it: it
// runs on every authenticated request.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, token string, p *Principal) (bool, error)
}

// RevocationCheckerFunc adapts a function to RevocationChecker.
type RevocationCheckerFunc func(ctx context.Context, token string, p *Principal) (bool, error)

// IsRevoked calls f.
func (f RevocationCheckerFunc) IsRevoked(ctx context.Context, token string, p *Principal) (bool, error) {
	return f(ctx, token, p)
}

// WithRevocationChecker installs a RevocationChecker. A token it reports
// revoked is answered 401 invalid_token. When the checker errors the request
// is refused too, unless WithRevocationFailOpen is set.
func WithRevocationChecker(c RevocationChecker) Option {
	return func(v *Validator) { v.revocation = c }
}

// WithRevocationFailOpen lets requests through when the RevocationChecker
// returns an error. Without it a failing checker denies the request.
func WithRevocationFailOpen() Option {
	return func(v *Validator) { v.revocationFailOpen = true }
}

// WithDeviceRevocationIntrospection checks tokens issued to devices (those
// carrying a device_id claim) against the AS introspection endpoint set with
// WithIntrospection, and passes every other token untouched. Answers are
// cached for WithCacheTTL, so a device revocation is seen within that window.
// It is shorthand for a RevocationChecker and replaces one set earlier.
func WithDeviceRevocationIntrospection() Option {
	return func(v *Validator) {
		v.revocation = deviceIntrospectionChecker{v: v}
	}
}

// deviceIntrospectionChecker asks the introspection cache whether a device
// token is still active.
type deviceIntrospectionChecker struct{ v *Validator }

func (c deviceIntrospectionChecker) IsRevoked(_ context.Context, token string, p *Principal) (bool, error) {
	if p.DeviceID == "" {
		return false, nil
	}
	if c.v.introspectURI == "" {
		return false, errors.New("mcpresource: device revocation introspection needs WithIntrospection")
	}
	res, err := c.v.introspect.Lookup(token, c.v.resourceURI)
	if err != nil {
		return false, err
	}
	if res == nil || !res.Active {
		c.v.introspect.Invalidate(token)
		return true, nil
	}
	return false, nil
}

var errTokenRevoked = newError("token revoked")

// checkRevocation runs the configured checker. It returns nil when no checker
// is set or the token is fine.
func (v *Validator) checkRevocation(r *http.Request, token string, p *Principal) error {
	if v.revocation == nil {
		return nil
	}
	revoked, err := v.revocation.IsRevoked(r.Context(), token, p)
	switch {
	case err != nil && v.revocationFailOpen:
		return nil
	case err != nil:
		return errors.New("mcpresource: revocation check failed")
	case revoked:
		return errTokenRevoked
	}
	return nil
}

package mqttauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig verifies a JWT sent as the MQTT password (RFC 7519). Keys usually come from the
// theAuth JWKS. The subject maps to Device.Subject, then to Device.ID.
type JWTConfig struct {
	// Keyfunc returns the verification key for the token. Required.
	Keyfunc jwt.Keyfunc
	// Methods lists the accepted signing algorithms, for example ES256. Required, so a token
	// can never pick its own algorithm (RFC 8725 section 3.1).
	Methods []string
	// Issuer and Audience are required and checked exactly.
	Issuer   string
	Audience string
	Leeway   time.Duration
}

func (c *JWTConfig) validate() error {
	if c.Keyfunc == nil || len(c.Methods) == 0 || c.Issuer == "" || c.Audience == "" {
		return errors.New("mqttauth: JWTConfig needs Keyfunc, Methods, Issuer and Audience")
	}
	return nil
}

// looksLikeJWT reports whether a password has the compact JWS shape.
func looksLikeJWT(s string) bool { return strings.Count(s, ".") == 2 && strings.HasPrefix(s, "eyJ") }

// verify returns the subject and expiry of a valid token.
func (c *JWTConfig) verify(tok string, now func() time.Time) (string, time.Time, error) {
	claims := jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(tok, &claims, c.Keyfunc,
		jwt.WithValidMethods(c.Methods), jwt.WithIssuer(c.Issuer), jwt.WithAudience(c.Audience),
		jwt.WithExpirationRequired(), jwt.WithLeeway(c.Leeway), jwt.WithTimeFunc(now))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt: %w", err)
	}
	if claims.Subject == "" || claims.ExpiresAt == nil {
		return "", time.Time{}, errors.New("jwt: missing sub or exp")
	}
	return claims.Subject, claims.ExpiresAt.Time, nil
}

func (h *Handler) deviceBySubject(ctx context.Context, sub string) (*Device, error) {
	d, err := h.cfg.Store.DeviceBySubject(ctx, sub)
	if errors.Is(err, ErrDeviceNotFound) {
		return h.cfg.Store.DeviceByID(ctx, sub)
	}
	return d, err
}

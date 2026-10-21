package device

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

// AssertionTyp is the `typ` header of a device assertion (design D3).
const AssertionTyp = "device-assertion+jwt"

const (
	// DefaultAudience is the audience the server expects unless `devices.audience` is set.
	DefaultAudience = "theauth"
	// DefaultAssertionTTL is used when AssertionOptions.TTL is zero.
	DefaultAssertionTTL = 60 * time.Second
	// MaxAssertionTTL is the server limit on exp minus iat (RFC 9449 section 11.1 window).
	MaxAssertionTTL = 300 * time.Second
	// skewSeconds is the tolerance every check in this package uses, same as the server.
	skewSeconds = 30
)

// AssertionOptions tunes SignAssertion.
type AssertionOptions struct {
	// Audience must equal the server's `devices.audience`. Default "theauth".
	Audience string
	// TTL is exp minus iat. Default 60 s, at most 300 s.
	TTL time.Duration
	// Rand supplies the jti bytes. Default crypto/rand.
	Rand io.Reader
}

// SignAssertion builds a short lived device assertion (RFC 7523 section 3 layout, RFC 9449
// replay rules) for `Authorization: Bearer <jwt>`. The header kid is the RFC 7638
// thumbprint of the signer's public key, which is how the server finds the credential.
// now must be the best time you have: a wrong clock makes the server reject the token.
func (s *Signer) SignAssertion(deviceID string, now time.Time, o AssertionOptions) (string, error) {
	if deviceID == "" {
		return "", errors.New("device: deviceID is required")
	}
	aud := o.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = DefaultAssertionTTL
	}
	if ttl < time.Second || ttl > MaxAssertionTTL {
		return "", errors.New("device: assertion TTL must be between 1s and 300s")
	}
	rng := o.Rand
	if rng == nil {
		rng = rand.Reader
	}
	jti := make([]byte, 16)
	if _, err := io.ReadFull(rng, jti); err != nil {
		return "", err
	}
	iat := now.Unix()
	return signJWS(s,
		map[string]any{"alg": string(s.pub.Alg), "typ": AssertionTyp, "kid": s.Public().KID},
		map[string]any{
			"iss": deviceID, "sub": deviceID, "aud": aud,
			"iat": iat, "exp": iat + int64(ttl/time.Second), "jti": b64.EncodeToString(jti),
		})
}

// VerifyAssertion checks an assertion the way the server does, except for the single use
// jti rule, which needs shared state (TS: verifyDeviceAssertion). It exists for gateways
// and tests. The server remains the authority.
func VerifyAssertion(token string, key PublicKey, deviceID, audience string, now time.Time) error {
	bad := errors.New("device: assertion invalid")
	t, err := parseJWS(token)
	if err != nil || !typMatches(t.header["typ"], AssertionTyp) || t.header["alg"] != string(key.Alg) {
		return bad
	}
	if !key.verifySig(t.input, t.sig) {
		return bad
	}
	pv, err := parseJSON(t.payload)
	claims, ok := pv.(map[string]any)
	if err != nil || !ok {
		return bad
	}
	nowSec := now.Unix()
	iat, ok1 := claims["iat"].(float64)
	exp, ok2 := claims["exp"].(float64)
	jti, ok3 := claims["jti"].(string)
	if !ok1 || !ok2 || !ok3 || int64(exp) <= nowSec-skewSeconds || int64(iat) > nowSec+skewSeconds {
		return bad
	}
	if claims["iss"] != deviceID || claims["sub"] != deviceID || exp-iat > float64(MaxAssertionTTL/time.Second) || exp <= iat {
		return bad
	}
	if !audienceHas(claims["aud"], audience) {
		return bad
	}
	if len(jti) < 16 || len(jti) > 256 {
		return bad
	}
	return nil
}

func audienceHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, e := range a {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

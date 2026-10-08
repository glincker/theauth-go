package as

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

// Clock is the time source used by the introspection cache and the
// chain-cache TTL. Config.Validate defaults this to realClock when nil, so
// production behavior is unchanged; tests inject a fake clock to assert
// revocation propagation deterministically instead of sleeping past the
// cache TTL.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock, a thin wrapper around time.Now.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// verifyAccessJWT verifies an access token JWT issued by this AS, applying
// the configured clock-skew tolerance to exp and nbf.
func (s *Service) verifyAccessJWT(token, expectedAud string, now time.Time) (jwt.Claims, error) {
	return jwt.VerifyOpts(token, s.PublicKeyByKID, expectedAud, now, jwt.VerifyOptions{Skew: s.Cfg.ClockSkew})
}

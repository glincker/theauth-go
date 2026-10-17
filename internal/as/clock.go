package as

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

// Clock is the time source for the introspection and chain caches. Config.Validate defaults it to
// the real clock; tests inject a fake clock to assert revocation deterministically.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// verifyAccessJWT verifies an access token issued by this AS, applying the configured clock-skew
// tolerance to exp and nbf.
func (s *Service) verifyAccessJWT(token, expectedAud string, now time.Time) (jwt.Claims, error) {
	return jwt.VerifyWith(token, s.VerificationKey, jwt.TypeAccessToken, expectedAud, now, jwt.VerifyOptions{Skew: s.Cfg.ClockSkew})
}

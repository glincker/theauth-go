package as

import (
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// OIDCConfig turns the authorization server into an OpenID Provider when
// non-nil: ID tokens for requests that carry the openid scope, the userinfo
// endpoint, RP-initiated logout and back-channel logout.
type OIDCConfig struct {
	// IDTokenTTL is the lifetime of an ID token. Defaults to AccessTokenTTL.
	IDTokenTTL time.Duration

	// PairwiseSalt keys the pairwise subject derivation. Required (at least
	// 16 bytes) when DefaultSubjectType is pairwise; without it clients
	// cannot register subject_type=pairwise.
	PairwiseSalt []byte

	// DefaultSubjectType is the subject type of clients that do not choose
	// one: "public" (default) or "pairwise".
	DefaultSubjectType string

	// BackchannelLogoutTimeout bounds one logout token delivery. Default 5s.
	BackchannelLogoutTimeout time.Duration

	// AllowPrivateNetworks lets back-channel logout reach loopback and
	// private addresses and plain http. Development and tests only.
	AllowPrivateNetworks bool

	// HTTPClient overrides the SSRF-guarded client used for back-channel
	// logout delivery.
	HTTPClient *http.Client
}

const minPairwiseSaltLen = 16

func applyOIDCDefaults(c *OIDCConfig, accessTTL time.Duration) {
	if c.IDTokenTTL <= 0 {
		c.IDTokenTTL = accessTTL
	}
	if c.DefaultSubjectType == "" {
		c.DefaultSubjectType = models.SubjectTypePublic
	}
	if c.BackchannelLogoutTimeout <= 0 {
		c.BackchannelLogoutTimeout = 5 * time.Second
	}
}

func validateOIDC(c *OIDCConfig) error {
	if c == nil {
		return nil
	}
	switch c.DefaultSubjectType {
	case "", models.SubjectTypePublic:
	case models.SubjectTypePairwise:
		if len(c.PairwiseSalt) < minPairwiseSaltLen {
			return errors.New("theauth: OIDC.PairwiseSalt must be at least 16 bytes when pairwise subjects are the default")
		}
	default:
		return errors.New("theauth: OIDC.DefaultSubjectType must be public or pairwise")
	}
	if len(c.PairwiseSalt) > 0 && len(c.PairwiseSalt) < minPairwiseSaltLen {
		return errors.New("theauth: OIDC.PairwiseSalt must be at least 16 bytes")
	}
	return nil
}

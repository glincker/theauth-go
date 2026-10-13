package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tenantPlaceholder is the multi-tenant issuer template marker used by
// Microsoft Entra ID for the common, organizations and consumers endpoints.
const tenantPlaceholder = "{tenantid}"

// multiTenantAliases are the Entra tenant segments that publish a
// discovery document whose issuer is the {tenantid} template.
var multiTenantAliases = []string{"common", "organizations", "consumers"}

// ClaimMapping names the ID token claims copied into the profile. An empty
// field keeps the OIDC standard claim (sub, email, email_verified, name,
// picture). A missing claim yields an empty value, and a missing
// EmailVerified claim yields false, never true.
type ClaimMapping struct {
	Subject       string
	Email         string
	EmailVerified string
	Name          string
	Picture       string
}

func (m ClaimMapping) or(def string, v string) string {
	if v != "" {
		return v
	}
	return def
}

// isTemplateIssuer reports whether iss is a {tenantid} template.
func isTemplateIssuer(iss string) bool { return strings.Contains(iss, tenantPlaceholder) }

// issuerAccepted reports whether the discovered issuer may stand in for the
// configured one: identical, or the discovered issuer is a {tenantid}
// template and the configured issuer is that template with one of the
// multi-tenant aliases substituted (for example .../common/v2.0).
func issuerAccepted(configured, discovered string) bool {
	if configured == discovered {
		return true
	}
	if !isTemplateIssuer(discovered) {
		return false
	}
	for _, alias := range multiTenantAliases {
		if strings.ReplaceAll(discovered, tenantPlaceholder, alias) == configured {
			return true
		}
	}
	return false
}

// validTenantID accepts the characters a tenant GUID or domain can hold, so a
// hostile tid cannot rewrite the template into another issuer.
func validTenantID(tid string) bool {
	if tid == "" || len(tid) > 128 {
		return false
	}
	for _, r := range tid {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

// verify checks the ID token signature, expiry, issuer and audience. With a
// {tenantid} template issuer the iss claim must equal the template filled
// with the token's own tid claim, and tid must be in AllowedTenants when
// that list is set.
func (p *provider) verify(ctx context.Context, raw string) (jwt.MapClaims, error) {
	claims, err := p.verifyClaims(ctx, raw)
	if err != nil {
		return nil, p.fail(StageVerify, 0, err)
	}
	return claims, nil
}

func (p *provider) verifyClaims(ctx context.Context, raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(p.cfg.AllowedAlgs),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
	}
	if p.template == "" {
		opts = append(opts, jwt.WithIssuer(p.cfg.Issuer))
	}
	_, err := jwt.NewParser(opts...).ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return p.keys.key(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	aud, err := claims.GetAudience()
	if err != nil || !p.audienceAccepted(aud) {
		return nil, errors.New("id_token audience not accepted")
	}
	if len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != p.cfg.ClientID {
			return nil, errors.New("id_token azp mismatch")
		}
	}
	if p.template != "" {
		if err := p.checkTenant(claims); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func (p *provider) audienceAccepted(aud []string) bool {
	for _, a := range aud {
		if a == p.cfg.ClientID || contains(p.cfg.AdditionalAudiences, a) {
			return true
		}
	}
	return false
}

func (p *provider) checkTenant(claims jwt.MapClaims) error {
	tid, _ := claims["tid"].(string)
	if !validTenantID(tid) {
		return errors.New("id_token has no valid tid claim")
	}
	if len(p.cfg.AllowedTenants) > 0 && !containsFold(p.cfg.AllowedTenants, tid) {
		return errors.New("id_token tenant is not allowed")
	}
	iss, _ := claims["iss"].(string)
	if iss != strings.ReplaceAll(p.template, tenantPlaceholder, tid) {
		return errors.New("id_token issuer does not match its tenant")
	}
	return nil
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

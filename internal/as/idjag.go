package as

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// idjag.go: Identity Assertion JWT Authorization Grant
// (draft-ietf-oauth-identity-assertion-authz-grant). Two halves:
//
//   - Issuing: a client exchanges an access token this server issued for a
//     short-lived ID-JAG addressed to another authorization server
//     (RFC 8693 with requested_token_type=...:id-jag).
//   - Redeeming: this server accepts an ID-JAG from a trusted issuer at the
//     jwt-bearer grant and mints an access token for the named client.

const (
	defaultIDJAGTTL = 5 * time.Minute
	maxIDJAGTTL     = 10 * time.Minute
)

// IDJAGConfig enables ID-JAG issuing and redemption.
type IDJAGConfig struct {
	// Audiences lists the authorization server issuer URLs an ID-JAG may be
	// addressed to. Required for issuing; a request for any other audience
	// is refused so a client cannot mint assertions for arbitrary servers.
	Audiences []string

	// TTL is the lifetime of an issued ID-JAG. Default 5 minutes, at most 10.
	TTL time.Duration
}

func validateIDJAG(cfg *Config) error {
	c := cfg.IDJAG
	if c == nil {
		return nil
	}
	for _, a := range c.Audiences {
		u, err := url.Parse(a)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("theauth: IDJAG.Audiences: %q must be an https issuer URL", a)
		}
	}
	switch {
	case c.TTL < 0, c.TTL > maxIDJAGTTL:
		return fmt.Errorf("theauth: IDJAG.TTL must be between 0 and %s", maxIDJAGTTL)
	case c.TTL == 0:
		c.TTL = defaultIDJAGTTL
	}
	return nil
}

// exchangeForIDJAG implements the issuing half. The subject token is an
// access token this server issued to the authenticated client.
func (s *Service) exchangeForIDJAG(ctx context.Context, req TokenExchangeRequest) (resp TokenResponse, err error) {
	cfg := s.Cfg.IDJAG
	if cfg == nil || len(cfg.Audiences) == 0 {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	ctx, span, timer := s.startTokenSpan(ctx, "token-exchange-id-jag")
	defer func() { s.finishTokenSpan(span, timer, "token-exchange-id-jag", err) }()
	client, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if req.SubjectToken == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.SubjectTokenType != "" && req.SubjectTokenType != models.TokenTypeAccessToken {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.Audience == "" || !stringIn(cfg.Audiences, req.Audience) {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	if req.Resource != "" {
		u, perr := url.Parse(req.Resource)
		if perr != nil || !u.IsAbs() || u.Fragment != "" {
			return TokenResponse{}, models.ErrOAuthInvalidResource
		}
	}
	now := s.Cfg.Clock.Now().UTC()
	subject, err := s.idJAGSubject(ctx, req.SubjectToken, now)
	if err != nil {
		return TokenResponse{}, err
	}
	if subject.ClientID != client.ClientID || strings.HasPrefix(subject.Sub, models.AgentSubjectPrefix) || subject.Sub == "" {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	// A DPoP-bound subject token may only be exchanged by the key holder.
	if jkt := cnfJKT(subject.Extra); jkt != "" {
		proof, perr := s.dpopThumbprintForRequest(TokenRequest{
			ClientID: client.ClientID, DPoPProof: req.DPoPProof,
			HTTPMethod: req.HTTPMethod, HTTPURL: req.HTTPURL,
		})
		if perr != nil {
			return TokenResponse{}, perr
		}
		if proof == "" || !jktEqual(proof, jkt) {
			return TokenResponse{}, fmt.Errorf("%w: subject token is DPoP-bound, matching proof required", ErrDPoPInvalid)
		}
	}
	scope := scopeSplit(subject.Scope)
	if len(req.Scope) > 0 {
		if !scopeSubset(req.Scope, scope) {
			return TokenResponse{}, models.ErrOAuthInvalidScope
		}
		scope = req.Scope
	}
	exp := now.Add(cfg.TTL)
	if subjectExp := time.Unix(subject.Exp, 0); subjectExp.Before(exp) {
		exp = subjectExp
	}
	claims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      subject.Sub,
		Aud:      req.Audience,
		Exp:      exp.Unix(),
		Iat:      now.Unix(),
		Jti:      ulid.New().String(),
		ClientID: client.ClientID,
		Scope:    scopeJoin(scope),
	}
	if req.Resource != "" {
		claims.Extra = map[string]any{"resource": req.Resource}
	}
	alg := s.defaultSigningAlg()
	key, signer, err := s.SigningKeyFor(ctx, alg)
	if err != nil {
		return TokenResponse{}, err
	}
	assertion, err := jwt.SignWith(claims, jwt.TypeIDJAG, key.KID, alg, signer)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign id-jag: %w", err)
	}
	s.Audit.EmitAudit(ctx, "id_jag.issued", models.TargetRef{Type: "user", ID: subject.Sub}, map[string]any{
		"client_id": client.ClientID,
		"audience":  req.Audience,
		"resource":  req.Resource,
		"scope":     scope,
		"jti":       claims.Jti,
	})
	return TokenResponse{
		AccessToken:     assertion,
		TokenType:       "N_A",
		ExpiresIn:       int(exp.Sub(now).Seconds()),
		Scope:           scopeJoin(scope),
		IssuedTokenType: models.TokenTypeIDJAG,
	}, nil
}

// idJAGSubject verifies the subject token (JWT or opaque) as an unrevoked
// access token issued by this server.
func (s *Service) idJAGSubject(ctx context.Context, token string, now time.Time) (jwt.Claims, error) {
	var claims jwt.Claims
	if strings.Count(token, ".") == 2 {
		c, err := s.verifyAccessJWT(token, "", now)
		if err != nil {
			return jwt.Claims{}, models.ErrSubjectTokenInvalid
		}
		claims = c
		if s.accessJTIRevoked(ctx, claims.Jti) {
			return jwt.Claims{}, models.ErrSubjectTokenInvalid
		}
	} else {
		c, ok := s.lookupOpaqueClaims(ctx, token)
		if !ok {
			return jwt.Claims{}, models.ErrSubjectTokenInvalid
		}
		claims = c
	}
	if claims.Iss != s.Cfg.Issuer {
		return jwt.Claims{}, models.ErrSubjectTokenInvalid
	}
	return claims, nil
}

// vetIDJAGRedemption applies the extra checks an ID-JAG needs on top of a
// plain RFC 7523 assertion and returns the scope to grant. The caller has
// already verified signature, issuer, audience and freshness.
func (s *Service) vetIDJAGRedemption(ctx context.Context, req TokenRequest, raw map[string]any) ([]string, error) {
	if s.Cfg.IDJAG == nil {
		return nil, models.ErrOAuthInvalidGrant
	}
	client, err := s.AuthenticateClientFromRequest(ctx, req, s.tokenEndpointURL())
	if err != nil {
		return nil, err
	}
	if cid, _ := raw["client_id"].(string); cid == "" || cid != client.ClientID {
		return nil, models.ErrOAuthInvalidGrant
	}
	if jti, _ := raw["jti"].(string); jti == "" {
		return nil, models.ErrOAuthInvalidGrant
	}
	if res, _ := raw["resource"].(string); res != "" && res != req.Resource {
		return nil, models.ErrOAuthInvalidGrant
	}
	assertionScope := scopeSplit(stringClaim(raw, "scope"))
	scope := assertionScope
	if len(req.Scope) > 0 {
		if !scopeSubset(req.Scope, assertionScope) {
			return nil, models.ErrOAuthInvalidScope
		}
		scope = req.Scope
	}
	if len(scope) == 0 {
		return nil, models.ErrOAuthInvalidScope
	}
	resource, ok := s.ResourceByIdentifier(req.Resource)
	if !ok {
		return nil, models.ErrOAuthInvalidResource
	}
	if _, err := validateScopeAgainstResource(scope, resource); err != nil {
		if errors.Is(err, models.ErrOAuthInvalidScope) {
			return nil, err
		}
		return nil, models.ErrOAuthInvalidScope
	}
	return scope, nil
}

func stringClaim(raw map[string]any, key string) string {
	v, _ := raw[key].(string)
	return v
}

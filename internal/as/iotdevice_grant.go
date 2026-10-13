package as

// iotdevice_grant.go: RFC 7523 jwt-bearer grant for registered devices. The
// assertion is signed with the device's enrolled key, with iss and sub set to
// the device ID and aud set to the token endpoint. Tokens are short lived,
// carry no refresh token, and are DPoP bound when the request has a proof.

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2/internal/chain"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// tryDeviceAssertion handles the assertion when its iss names a registered
// device. handled is false when it does not, so the caller falls through to
// the trusted issuer path.
func (s *Service) tryDeviceAssertion(ctx context.Context, req TokenRequest, assertion string) (resp TokenResponse, handled bool, err error) {
	store, ok := s.identityStore()
	if !ok {
		return TokenResponse{}, false, nil
	}
	header, claims, signingInput, sig, perr := parseGenericJWT(assertion)
	if perr != nil || claims.Iss == "" || claims.Iss != claims.Sub {
		return TokenResponse{}, false, nil
	}
	id, perr := parseULID(claims.Iss)
	if perr != nil {
		return TokenResponse{}, false, nil
	}
	dev, derr := store.DeviceByID(ctx, id)
	if errors.Is(derr, models.ErrStorageNotFound) {
		return TokenResponse{}, false, nil
	}
	if derr != nil {
		return TokenResponse{}, true, derr
	}
	ctx, span, timer := s.startTokenSpan(ctx, "device-assertion")
	defer func() { s.finishTokenSpan(span, timer, "device-assertion", err) }()
	resp, err = s.deviceAssertionGrant(ctx, store, req, dev, header, claims, signingInput, sig)
	return resp, true, err
}

func (s *Service) deviceAssertionGrant(ctx context.Context, store DeviceIdentityStorage, req TokenRequest, dev *models.Device,
	header genericJWTHeader, claims genericJWTClaims, signingInput string, sig []byte) (TokenResponse, error) {
	cfg := s.Cfg.DeviceTokens
	now := s.now().UTC()
	if !dev.Active() {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Aud != s.tokenEndpointURL() || claims.Exp == 0 || claims.Iat == 0 || claims.Jti == "" {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	exp, iat := time.Unix(claims.Exp, 0), time.Unix(claims.Iat, 0)
	skew := s.Cfg.ClockSkew
	if exp.Add(skew).Before(now) || iat.Add(-skew).After(now) || exp.Sub(iat) > cfg.AssertionMaxLifetime {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if claims.Nbf != 0 && time.Unix(claims.Nbf, 0).Add(-skew).After(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	key, err := parseDeviceKey(dev.PublicKeyJWK)
	if err != nil || header.Alg != key.entry.Alg {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if !verifyWithJWKS([]jwksEntry{key.entry}, header, []byte(signingInput), sig) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// The device is authenticated from here on, so its budget is charged
	// before anything single use is spent and a limited device can retry.
	if err := s.deviceLimit(ctx, "token", dev.ID.String(), cfg.TokenPerMinute); err != nil {
		return TokenResponse{}, err
	}
	// Resource and scope are checked before the proof and jti are spent, so a
	// bad request does not burn an assertion the device could still use.
	audience, scope, err := s.deviceResourceScope(req, dev)
	if err != nil {
		return TokenResponse{}, err
	}
	jkt, err := s.dpopThumbprintForRequest(req)
	if err != nil {
		return TokenResponse{}, err
	}
	// The jti is recorded only after the signature verified, so an
	// unauthenticated caller cannot fill the replay cache.
	replayUntil := exp.Add(s.jtiReplayTTL())
	if rerr := s.jtiReplayCheck(ctx, "device:"+dev.ID.String()+":"+claims.Jti, replayUntil); rerr != nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}

	jti := ulid.New().String()
	out := jwt.Claims{
		Iss: s.Cfg.Issuer, Sub: dev.Subject(), Aud: audience,
		Exp: now.Add(cfg.AccessTokenTTL).Unix(), Iat: now.Unix(), Jti: jti,
		ClientID: dev.ID.String(), Scope: scopeJoin(scope), Typ: jwt.TypeAccessToken,
		Extra: map[string]any{"device_id": dev.ID.String()},
	}
	if dev.OrganizationID != nil {
		out.Extra["organization_id"] = dev.OrganizationID.String()
	}
	tokenType := "Bearer"
	if jkt != "" {
		out.Extra["cnf"] = map[string]string{"jkt": jkt}
		tokenType = "DPoP"
	}
	if err := s.applyOnTokenIssued(ctx, &out); err != nil {
		return TokenResponse{}, err
	}
	access, err := s.issueAccessToken(ctx, out.ClientID, out)
	if err != nil {
		return TokenResponse{}, err
	}
	if terr := store.TouchDevice(ctx, dev.ID, now); terr != nil {
		s.Audit.EmitAudit(ctx, "device.touch_failed", models.TargetRef{Type: "device", ID: dev.ID.String()},
			map[string]any{"error": terr.Error()})
	}
	s.Audit.EmitAudit(ctx, "device.token_minted", models.TargetRef{Type: "device", ID: dev.ID.String()}, map[string]any{
		"jti": jti, "resource": audience, "scope": scope, "dpop_bound": jkt != "", "grant": models.GrantTypeJWTBearer,
	})
	return TokenResponse{
		AccessToken: access, TokenType: tokenType,
		ExpiresIn: int(cfg.AccessTokenTTL.Seconds()), Scope: scopeJoin(scope),
	}, nil
}

// deviceResourceScope resolves the audience and narrows the scope to the
// device's enrolled scopes and the resource's scopes. With a single configured
// resource, the resource parameter is optional.
func (s *Service) deviceResourceScope(req TokenRequest, dev *models.Device) (string, []string, error) {
	raw := req.Resource
	if raw == "" && len(s.Cfg.Resources) == 1 {
		raw = s.Cfg.Resources[0].Identifier
	}
	res, audience, err := s.resolveResource(raw)
	if err != nil {
		return "", nil, err
	}
	available := chain.ScopeIntersect(dev.Scopes, res.Scopes)
	scope := req.Scope
	if len(scope) == 0 {
		scope = available
	} else if !chain.ScopeSubset(scope, available) {
		return "", nil, models.ErrOAuthInvalidScope
	}
	if len(scope) == 0 {
		return "", nil, models.ErrOAuthInvalidScope
	}
	return audience, scope, nil
}

func (s *Service) jtiReplayTTL() time.Duration {
	if s.Cfg.JWTBearer != nil && s.Cfg.JWTBearer.ReplayCacheTTL > 0 {
		return s.Cfg.JWTBearer.ReplayCacheTTL
	}
	return 10 * time.Minute
}

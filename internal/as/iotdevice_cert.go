package as

// iotdevice_cert.go mints an RFC 8705 certificate bound access token for a device that the caller
// already authenticated with an X.509-SVID (see iot/spiffe). The token carries cnf x5t#S256, so a
// resource server (mcpresource) accepts it only on a TLS connection that presents that certificate.
// The grant is not reachable over HTTP: authenticating the certificate is the caller's job, and the
// caller must know the peer holds the private key (a verified TLS handshake).

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// DeviceCertTokenRequest asks for a certificate bound token for one device.
type DeviceCertTokenRequest struct {
	DeviceID models.ULID
	// X5tS256 is the RFC 8705 section 3.1 thumbprint of the leaf certificate: base64url, no padding,
	// of the SHA-256 digest of the DER encoding.
	X5tS256 string
	// Resource and Scope pick the audience and narrow the scopes, the same rules as the assertion grant.
	Resource string
	Scope    []string
	// NotAfter is the certificate expiry. The token never outlives it. Zero means no extra cap.
	NotAfter time.Time
}

// IssueDeviceCertToken mints a short lived access token bound to a client certificate. It needs
// Config.DeviceTokens, refuses an inactive device, shares the per device token rate budget and
// audits the mint like an assertion grant. No refresh token is issued.
func (s *Service) IssueDeviceCertToken(ctx context.Context, req DeviceCertTokenRequest) (TokenResponse, error) {
	store, ok := s.identityStore()
	if !ok || s.Cfg.DeviceTokens == nil {
		return TokenResponse{}, models.ErrDevicesDisabled
	}
	if raw, err := base64.RawURLEncoding.DecodeString(req.X5tS256); err != nil || len(raw) != 32 {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	dev, err := store.DeviceByID(ctx, req.DeviceID)
	if err != nil {
		return TokenResponse{}, err
	}
	if !dev.Active() {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	cfg := s.Cfg.DeviceTokens
	now := s.now().UTC()
	ttl := cfg.AccessTokenTTL
	if !req.NotAfter.IsZero() {
		if left := req.NotAfter.Sub(now); left < ttl {
			ttl = left
		}
	}
	if ttl <= 0 {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if err := s.deviceLimit(ctx, "token", dev.ID.String(), cfg.TokenPerMinute); err != nil {
		return TokenResponse{}, err
	}
	audience, scope, err := s.deviceResourceScope(TokenRequest{Resource: req.Resource, Scope: req.Scope}, dev)
	if err != nil {
		return TokenResponse{}, err
	}
	jti := ulid.New().String()
	out := jwt.Claims{
		Iss: s.Cfg.Issuer, Sub: dev.Subject(), Aud: audience,
		Exp: now.Add(ttl).Unix(), Iat: now.Unix(), Jti: jti,
		ClientID: dev.ID.String(), Scope: scopeJoin(scope), Typ: jwt.TypeAccessToken,
		Extra: map[string]any{
			"device_id": dev.ID.String(),
			"cnf":       map[string]string{"x5t#S256": req.X5tS256},
		},
	}
	if dev.OrganizationID != nil {
		out.Extra["organization_id"] = dev.OrganizationID.String()
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
		"jti": jti, "resource": audience, "scope": scope, "mtls_bound": true, "grant": "svid_x509",
	})
	// RFC 8705 section 3: a certificate bound token is still presented as a Bearer token.
	return TokenResponse{
		AccessToken: access, TokenType: "Bearer",
		ExpiresIn: int(ttl.Seconds()), Scope: scopeJoin(scope),
	}, nil
}

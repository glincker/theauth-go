package as

// iotdevice.go: constrained device identity. An admin mints a single-use join
// token; the device presents it with its public key and proves possession by
// signing a server challenge; the server registers a Device. Registered
// devices then authenticate to the token endpoint with an RFC 7523 assertion
// (see iotdevice_grant.go). Attestation is pluggable through Attestor.

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

const (
	joinTokenPrefix = "dj_"
	// challengeTyp and proofTyp are the JOSE typ values of the server
	// challenge and the device's proof of possession.
	challengeTyp = "device-challenge+jwt"
	proofTyp     = "device-enroll+jwt"

	// DefaultDeviceTokenTTL is the default access token lifetime for devices.
	DefaultDeviceTokenTTL = 10 * time.Minute
	// DefaultDeviceJoinTokenTTL is the default join token lifetime.
	DefaultDeviceJoinTokenTTL = time.Hour
	// DefaultDeviceChallengeTTL is how long an enrollment challenge is valid.
	DefaultDeviceChallengeTTL = 2 * time.Minute
	// DefaultDeviceAssertionLifetime caps exp minus iat on device assertions.
	DefaultDeviceAssertionLifetime = 5 * time.Minute
)

// DeviceTokensConfig enables device enrollment and the device assertion grant.
type DeviceTokensConfig struct {
	// AccessTokenTTL is the lifetime of device access tokens. Default 10m.
	// Devices get no refresh token; they re-assert when the token expires.
	AccessTokenTTL time.Duration
	// JoinTokenTTL is the default join token lifetime. Default 1h.
	JoinTokenTTL time.Duration
	// ChallengeTTL bounds the enrollment challenge. Default 2m.
	ChallengeTTL time.Duration
	// AssertionMaxLifetime caps exp minus iat on assertions. Default 5m.
	AssertionMaxLifetime time.Duration
	// EnrollPerMinute caps challenge and enroll requests per join token per
	// minute. Counted only for join tokens that exist and are usable, so a
	// stranger cannot exhaust someone else's token. Default 10, negative
	// turns it off.
	EnrollPerMinute int
	// TokenPerMinute caps assertion grants per device per minute. Counted
	// only after the assertion signature verified. Default 60, negative
	// turns it off.
	TokenPerMinute int
}

func applyDeviceTokenDefaults(c *DeviceTokensConfig) {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = DefaultDeviceTokenTTL
	}
	if c.JoinTokenTTL <= 0 {
		c.JoinTokenTTL = DefaultDeviceJoinTokenTTL
	}
	if c.ChallengeTTL <= 0 {
		c.ChallengeTTL = DefaultDeviceChallengeTTL
	}
	if c.AssertionMaxLifetime <= 0 {
		c.AssertionMaxLifetime = DefaultDeviceAssertionLifetime
	}
	if c.EnrollPerMinute == 0 {
		c.EnrollPerMinute = DefaultDeviceEnrollPerMinute
	}
	if c.TokenPerMinute == 0 {
		c.TokenPerMinute = DefaultDeviceTokenPerMinute
	}
}

// Default per device request budgets.
const (
	DefaultDeviceEnrollPerMinute = 10
	DefaultDeviceTokenPerMinute  = 60
)

// RateLimitedError reports a per device budget that is used up.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return "theauth: device rate limit exceeded" }

// deviceLimit spends one unit of the per minute budget for id under rule. It
// fails open when the limiter backend errors, like the HTTP limits.
func (s *Service) deviceLimit(ctx context.Context, rule, id string, limit int) error {
	if limit <= 0 || s.Limiter == nil {
		return nil
	}
	d, err := s.Limiter.Allow(ctx, "as:device:"+rule+":"+id, limit, time.Minute)
	if err != nil {
		slog.Warn("theauth: device rate limiter unavailable, failing open", "rule", rule, "err", err.Error())
		return nil
	}
	if d.Allowed {
		return nil
	}
	s.Hooks.Counter(obs.MetricRateLimitBlockedTotal, obs.Labels{obs.AttrRule: "device_" + rule}).Inc()
	return &RateLimitedError{RetryAfter: d.RetryAfter}
}

// DeviceEvidence is what an enrolling device presents to an Attestor.
type DeviceEvidence struct {
	Kind         string
	Token        string
	PublicKeyJWK []byte
	Thumbprint   string
}

// DeviceAttestation is the identity an Attestor grants. The enrolling device
// receives exactly this identity; it cannot choose its own.
type DeviceAttestation struct {
	Kind           string
	Subject        string
	OrganizationID *models.ULID
	Name           string
	SPIFFEID       string
	Scopes         []string
}

// Attestor decides whether evidence entitles a device to an identity. The
// join token attestor is built in; x509 proof of possession or TPM attestors
// implement the same interface.
type Attestor interface {
	Kind() string
	// Attest validates evidence without consuming it.
	Attest(ctx context.Context, ev DeviceEvidence) (DeviceAttestation, error)
	// Consume spends single-use evidence for deviceID. It must fail when the
	// evidence was already spent.
	Consume(ctx context.Context, a DeviceAttestation, deviceID models.ULID) error
	// Release undoes Consume when registration failed afterwards.
	Release(ctx context.Context, a DeviceAttestation) error
}

type joinTokenAttestor struct {
	store DeviceIdentityStorage
	now   func() time.Time
}

func (joinTokenAttestor) Kind() string { return models.DeviceAttestationJoinToken }

func (a joinTokenAttestor) Attest(ctx context.Context, ev DeviceEvidence) (DeviceAttestation, error) {
	if ev.Token == "" {
		return DeviceAttestation{}, models.ErrDeviceEnrollmentInvalid
	}
	t, err := a.store.DeviceJoinTokenByHash(ctx, crypto.HashToken(ev.Token))
	if err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return DeviceAttestation{}, models.ErrDeviceEnrollmentInvalid
		}
		return DeviceAttestation{}, err
	}
	if !t.Active(a.now()) {
		return DeviceAttestation{}, models.ErrDeviceEnrollmentInvalid
	}
	return DeviceAttestation{
		Kind: models.DeviceAttestationJoinToken, Subject: t.ID.String(), OrganizationID: t.OrganizationID,
		Name: t.Name, SPIFFEID: t.SPIFFEID, Scopes: append([]string(nil), t.Scopes...),
	}, nil
}

func (a joinTokenAttestor) Consume(ctx context.Context, att DeviceAttestation, deviceID models.ULID) error {
	id, err := parseULID(att.Subject)
	if err != nil {
		return models.ErrDeviceEnrollmentInvalid
	}
	won, err := a.store.RedeemDeviceJoinToken(ctx, id, deviceID, a.now())
	if err != nil {
		return err
	}
	if !won {
		return models.ErrDeviceEnrollmentInvalid
	}
	return nil
}

func (a joinTokenAttestor) Release(ctx context.Context, att DeviceAttestation) error {
	id, err := parseULID(att.Subject)
	if err != nil {
		return nil
	}
	return a.store.RefundDeviceJoinToken(ctx, id)
}

func (s *Service) identityStore() (DeviceIdentityStorage, bool) {
	if s == nil || s.Cfg.DeviceTokens == nil {
		return nil, false
	}
	st, ok := s.Storage.(DeviceIdentityStorage)
	return st, ok
}

// DeviceTokensEnabled reports whether device tokens are configured and the
// storage can hold devices.
func (s *Service) DeviceTokensEnabled() bool {
	_, ok := s.identityStore()
	return ok
}

func (s *Service) attestor(store DeviceIdentityStorage, kind string) (Attestor, bool) {
	if kind == "" || kind == models.DeviceAttestationJoinToken {
		return joinTokenAttestor{store: store, now: s.now}, true
	}
	return nil, false
}

// CreateDeviceJoinTokenInput describes a join token to mint.
type CreateDeviceJoinTokenInput struct {
	OrganizationID *models.ULID
	// Name and SPIFFEID are the identity the enrolling device receives.
	Name     string
	SPIFFEID string
	// Scopes caps the scopes the device's tokens may carry. Required.
	Scopes []string
	// TTL defaults to DeviceTokensConfig.JoinTokenTTL.
	TTL       time.Duration
	CreatedBy *models.ULID
}

// CreateDeviceJoinToken mints a single-use join token and returns the stored
// record plus the plaintext, which is not recoverable afterwards.
func (s *Service) CreateDeviceJoinToken(ctx context.Context, in CreateDeviceJoinTokenInput) (models.DeviceJoinToken, string, error) {
	store, ok := s.identityStore()
	if !ok {
		return models.DeviceJoinToken{}, "", models.ErrDevicesDisabled
	}
	if len(in.Scopes) == 0 || in.TTL < 0 {
		return models.DeviceJoinToken{}, "", models.ErrOAuthInvalidRequest
	}
	if in.TTL == 0 {
		in.TTL = s.Cfg.DeviceTokens.JoinTokenTTL
	}
	secret, err := crypto.NewToken()
	if err != nil {
		return models.DeviceJoinToken{}, "", err
	}
	raw := joinTokenPrefix + secret
	now := s.now().UTC()
	t := models.DeviceJoinToken{
		ID: ulid.New(), TokenHash: crypto.HashToken(raw), Prefix: raw[:len(joinTokenPrefix)+4],
		OrganizationID: in.OrganizationID, Name: in.Name, SPIFFEID: in.SPIFFEID,
		Scopes: append([]string(nil), in.Scopes...), CreatedBy: in.CreatedBy,
		CreatedAt: now, ExpiresAt: now.Add(in.TTL),
	}
	if err := store.InsertDeviceJoinToken(ctx, t); err != nil {
		return models.DeviceJoinToken{}, "", err
	}
	s.Audit.EmitAudit(ctx, "device.join_token.created",
		models.TargetRef{Type: "device_join_token", ID: t.ID.String()},
		map[string]any{"name": t.Name, "spiffe_id": t.SPIFFEID, "expires_at": t.ExpiresAt.Format(time.RFC3339)})
	return t, raw, nil
}

// DeviceEnrollRequest carries the enrollment fields. Challenge and Proof are
// empty on the challenge step.
type DeviceEnrollRequest struct {
	Kind      string
	JoinToken string
	JWK       json.RawMessage
	Challenge string
	Proof     string
	Name      string
}

// DeviceChallenge is the server nonce a device must sign.
type DeviceChallenge struct {
	Challenge string `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

// deviceKey is a validated device public key.
type deviceKey struct {
	jwk        json.RawMessage // canonical public JWK
	thumbprint string
	entry      jwksEntry
}

// parseDeviceKey accepts EC P-256, EC P-384 and OKP Ed25519 public keys and
// rejects private key members.
func parseDeviceKey(raw []byte) (deviceKey, error) {
	var j dpop.JWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return deviceKey{}, fmt.Errorf("device jwk: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return deviceKey{}, fmt.Errorf("device jwk: %w", err)
	}
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, has := members[priv]; has {
			return deviceKey{}, errors.New("device jwk: private key material present")
		}
	}
	var canonical any
	switch {
	case j.Kty == "EC" && (j.Crv == "P-256" || j.Crv == "P-384"):
		canonical = map[string]string{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y}
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		canonical = map[string]string{"kty": j.Kty, "crv": j.Crv, "x": j.X}
	default:
		return deviceKey{}, errors.New("device jwk: unsupported key type")
	}
	cj, err := json.Marshal(canonical)
	if err != nil {
		return deviceKey{}, err
	}
	entries, err := parseJWKSBytes([]byte(`{"keys":[` + string(cj) + `]}`))
	if err != nil || len(entries) != 1 {
		return deviceKey{}, errors.New("device jwk: unusable key")
	}
	if pk, ok := entries[0].Key.(*ecdsa.PublicKey); ok {
		if _, err := pk.ECDH(); err != nil {
			return deviceKey{}, errors.New("device jwk: point not on curve")
		}
	}
	tp, err := dpop.Thumbprint(&dpop.JWK{Kty: j.Kty, Crv: j.Crv, X: j.X, Y: j.Y})
	if err != nil {
		return deviceKey{}, err
	}
	return deviceKey{jwk: cj, thumbprint: tp, entry: entries[0]}, nil
}

// DeviceEnrollChallenge validates the evidence and returns a server nonce
// bound to the evidence and the device key. It consumes nothing.
func (s *Service) DeviceEnrollChallenge(ctx context.Context, req DeviceEnrollRequest) (DeviceChallenge, error) {
	store, ok := s.identityStore()
	if !ok {
		return DeviceChallenge{}, models.ErrDevicesDisabled
	}
	key, err := parseDeviceKey(req.JWK)
	if err != nil {
		return DeviceChallenge{}, models.ErrDeviceEnrollmentInvalid
	}
	att, err := s.attestDevice(ctx, store, req, key)
	if err != nil {
		return DeviceChallenge{}, err
	}
	if err := s.deviceLimit(ctx, "enroll", att.Subject, s.Cfg.DeviceTokens.EnrollPerMinute); err != nil {
		return DeviceChallenge{}, err
	}
	alg := s.defaultSigningAlg()
	jk, signer, err := s.SigningKeyFor(ctx, alg)
	if err != nil {
		return DeviceChallenge{}, err
	}
	now := s.now().UTC()
	ttl := s.Cfg.DeviceTokens.ChallengeTTL
	claims := jwt.Claims{
		Iss: s.Cfg.Issuer, Sub: att.Subject, Aud: s.Cfg.Issuer,
		Exp: now.Add(ttl).Unix(), Iat: now.Unix(), Jti: ulid.New().String(), Typ: challengeTyp,
		Extra: map[string]any{"jkt": key.thumbprint, "kind": att.Kind},
	}
	tok, err := jwt.SignWith(claims, challengeTyp, jk.KID, alg, signer)
	if err != nil {
		return DeviceChallenge{}, fmt.Errorf("sign device challenge: %w", err)
	}
	return DeviceChallenge{Challenge: tok, ExpiresIn: int(ttl.Seconds())}, nil
}

func (s *Service) attestDevice(ctx context.Context, store DeviceIdentityStorage, req DeviceEnrollRequest, key deviceKey) (DeviceAttestation, error) {
	a, ok := s.attestor(store, req.Kind)
	if !ok {
		return DeviceAttestation{}, models.ErrDeviceEnrollmentInvalid
	}
	return a.Attest(ctx, DeviceEvidence{Kind: a.Kind(), Token: req.JoinToken, PublicKeyJWK: key.jwk, Thumbprint: key.thumbprint})
}

// EnrollDevice completes enrollment: it verifies the challenge and the
// device's proof of possession, spends the evidence and registers the device.
func (s *Service) EnrollDevice(ctx context.Context, req DeviceEnrollRequest) (models.Device, error) {
	store, ok := s.identityStore()
	if !ok {
		return models.Device{}, models.ErrDevicesDisabled
	}
	key, err := parseDeviceKey(req.JWK)
	if err != nil {
		return models.Device{}, models.ErrDeviceEnrollmentInvalid
	}
	att, err := s.attestDevice(ctx, store, req, key)
	if err != nil {
		return models.Device{}, err
	}
	if err := s.deviceLimit(ctx, "enroll", att.Subject, s.Cfg.DeviceTokens.EnrollPerMinute); err != nil {
		return models.Device{}, err
	}
	now := s.now().UTC()
	ch, err := jwt.VerifyWith(req.Challenge, s.VerificationKey, challengeTyp, s.Cfg.Issuer, now,
		jwt.VerifyOptions{Skew: s.Cfg.ClockSkew})
	if err != nil || ch.Sub != att.Subject {
		return models.Device{}, models.ErrDeviceEnrollmentInvalid
	}
	if jkt, _ := ch.Extra["jkt"].(string); jkt != key.thumbprint {
		return models.Device{}, models.ErrDeviceEnrollmentInvalid
	}
	if !s.verifyEnrollProof(req.Proof, key, ch.Jti, now) {
		return models.Device{}, models.ErrDeviceEnrollmentInvalid
	}
	a, _ := s.attestor(store, req.Kind)
	id := ulid.New()
	if err := a.Consume(ctx, att, id); err != nil {
		return models.Device{}, err
	}
	name := att.Name
	if name == "" {
		name = req.Name
	}
	d := models.Device{
		ID: id, OrganizationID: att.OrganizationID, Name: name, SPIFFEID: att.SPIFFEID,
		PublicKeyJWK: key.jwk, KeyThumbprint: key.thumbprint, Attestation: att.Kind,
		Scopes: att.Scopes, Status: models.DeviceStatusActive, CreatedAt: now,
	}
	if err := store.InsertDevice(ctx, d); err != nil {
		if rerr := a.Release(ctx, att); rerr != nil {
			s.Audit.EmitAudit(ctx, "device.enroll.release_failed",
				models.TargetRef{Type: "device_join_token", ID: att.Subject}, map[string]any{"error": rerr.Error()})
		}
		return models.Device{}, err
	}
	s.Audit.EmitAudit(ctx, "device.enrolled", models.TargetRef{Type: "device", ID: id.String()},
		map[string]any{"name": d.Name, "spiffe_id": d.SPIFFEID, "attestation": d.Attestation, "jkt": d.KeyThumbprint})
	return d, nil
}

// verifyEnrollProof checks the device's signature over the challenge nonce.
func (s *Service) verifyEnrollProof(proof string, key deviceKey, nonce string, now time.Time) bool {
	header, claims, signingInput, sig, err := parseGenericJWT(proof)
	if err != nil || header.Typ != proofTyp || header.Alg != key.entry.Alg {
		return false
	}
	if claims.Aud != s.Cfg.Issuer || claims.Exp == 0 {
		return false
	}
	skew := s.Cfg.ClockSkew
	if time.Unix(claims.Exp, 0).Add(skew).Before(now) {
		return false
	}
	if got, _ := claims.raw["nonce"].(string); got == "" || got != nonce {
		return false
	}
	return verifyWithJWKS([]jwksEntry{key.entry}, header, []byte(signingInput), sig)
}

// ListDevices lists registered devices, newest first. A nil orgID lists all.
func (s *Service) ListDevices(ctx context.Context, orgID *models.ULID) ([]models.Device, error) {
	store, ok := s.identityStore()
	if !ok {
		return nil, models.ErrDevicesDisabled
	}
	return store.ListDevices(ctx, orgID)
}

// RevokeDevice revokes a device. When orgID is non-nil the device must belong
// to that organization, otherwise ErrStorageNotFound is returned. Revoking an
// already revoked device is a no-op.
func (s *Service) RevokeDevice(ctx context.Context, id models.ULID, orgID *models.ULID, actor *models.ULID) error {
	store, ok := s.identityStore()
	if !ok {
		return models.ErrDevicesDisabled
	}
	d, err := store.DeviceByID(ctx, id)
	if err != nil {
		return err
	}
	if orgID != nil && (d.OrganizationID == nil || *d.OrganizationID != *orgID) {
		return models.ErrStorageNotFound
	}
	changed, err := store.RevokeDevice(ctx, id, s.now().UTC())
	if err != nil {
		return err
	}
	if changed {
		meta := map[string]any{"name": d.Name}
		if actor != nil {
			meta["revoked_by"] = actor.String()
		}
		s.Audit.EmitAudit(ctx, "device.revoked", models.TargetRef{Type: "device", ID: id.String()}, meta)
	}
	return nil
}

// RevokeDeviceJoinToken revokes an unspent join token, scoped like RevokeDevice.
func (s *Service) RevokeDeviceJoinToken(ctx context.Context, id models.ULID, orgID *models.ULID) error {
	store, ok := s.identityStore()
	if !ok {
		return models.ErrDevicesDisabled
	}
	t, err := store.DeviceJoinTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if orgID != nil && (t.OrganizationID == nil || *t.OrganizationID != *orgID) {
		return models.ErrStorageNotFound
	}
	_, err = store.RevokeDeviceJoinToken(ctx, id, s.now().UTC())
	return err
}

// deviceActive reports whether the device exists and is not revoked. It fails
// closed when the storage cannot answer.
func (s *Service) deviceActive(ctx context.Context, id string) bool {
	store, ok := s.identityStore()
	if !ok {
		return false
	}
	did, err := parseULID(id)
	if err != nil {
		return false
	}
	d, err := store.DeviceByID(ctx, did)
	return err == nil && d.Active()
}

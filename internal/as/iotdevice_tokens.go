package as

// iotdevice_tokens.go mints device enrollment tokens in three shapes, as the TS device registry
// does: a single use join token, a claim code (one device, a short code a person types) and a bulk
// token (many devices, one long token for a factory line). All three are rows of
// DeviceJoinToken: single use is MaxUses 1, bulk is MaxUses above one, a claim code differs only in
// how the secret is spelled.

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Join token kinds for CreateDeviceJoinTokenInput.Kind.
const (
	// JoinTokenKindSingle is the default: one "dj_" token, one device.
	JoinTokenKindSingle = ""
	// JoinTokenKindClaim is one device and a short code, XXXXX-XXXXX, for a person to type.
	JoinTokenKindClaim = "claim"
	// JoinTokenKindBulk is a "dj_" token that enrolls up to MaxUses devices.
	JoinTokenKindBulk = "bulk"
)

const (
	// DefaultDeviceClaimCodeTTL is the claim code lifetime when TTL is zero.
	DefaultDeviceClaimCodeTTL = 15 * time.Minute
	// DefaultDeviceBulkTokenTTL is the bulk token lifetime when TTL is zero.
	DefaultDeviceBulkTokenTTL = 24 * time.Hour
	// MaxDeviceEnrollmentTTL caps the lifetime of claim codes and bulk tokens.
	MaxDeviceEnrollmentTTL = 30 * 24 * time.Hour
	// MaxDeviceBulkUses caps MaxUses of a bulk token.
	MaxDeviceBulkUses = 1_000_000

	claimCodeLen    = 10
	claimCodeAlpha  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford base32: no I, L, O or U
	claimHashDomain = "theauth-device-claim\n"
)

// CreateDeviceJoinTokenInput describes a device join token to mint.
type CreateDeviceJoinTokenInput struct {
	OrganizationID *models.ULID
	Name           string
	SPIFFEID       string
	Scopes         []string
	// TTL is the token lifetime. Zero means DeviceTokensConfig.JoinTokenTTL, or the claim code and
	// bulk defaults. Claim codes and bulk tokens may not live longer than MaxDeviceEnrollmentTTL.
	TTL time.Duration
	// Kind is JoinTokenKindSingle (default), JoinTokenKindClaim or JoinTokenKindBulk.
	Kind string
	// MaxUses is the number of devices a bulk token may enroll (1 to MaxDeviceBulkUses, required;
	// above 1 it cannot fix a SPIFFEID because that is unique per device).
	// Single and claim tokens allow one and reject any other value.
	MaxUses   int
	CreatedBy *models.ULID
}

// generateClaimCode returns 10 Crockford characters (50 bits) as XXXXX-XXXXX.
func generateClaimCode() (string, error) {
	b := make([]byte, claimCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, claimCodeLen)
	for i, v := range b {
		out[i] = claimCodeAlpha[v&31] // 32 symbols, so the mask is unbiased
	}
	return string(out[:5]) + "-" + string(out[5:]), nil
}

// canonicalClaimCode folds what a person typed into the stored form: case, dashes and spaces
// ignored, and the Crockford look alikes read as digits (I and L as 1, O as 0). It reports false
// when the result is not a claim code.
func canonicalClaimCode(in string) (string, bool) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch r {
		case ' ', '\t', '\n', '\r', '-':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if r > 127 || !strings.ContainsRune(claimCodeAlpha, r) {
			return "", false
		}
		sb.WriteRune(r)
	}
	if sb.Len() != claimCodeLen {
		return "", false
	}
	return sb.String(), true
}

// enrollmentTokenHash maps a presented secret to the digest stored for it. "dj_" tokens hash as
// they are. Anything else must be a claim code and hashes under its own domain, so a claim code
// can never collide with a join token digest.
func enrollmentTokenHash(token string) ([]byte, bool) {
	if strings.HasPrefix(token, joinTokenPrefix) {
		return crypto.HashToken(token), true
	}
	code, ok := canonicalClaimCode(token)
	if !ok {
		return nil, false
	}
	return crypto.HashToken(claimHashDomain + code), true
}

// CreateDeviceJoinToken mints a join token. The plaintext is returned once and is not recoverable
// afterwards. For a claim code the plaintext is the XXXXX-XXXXX code.
func (s *Service) CreateDeviceJoinToken(ctx context.Context, in CreateDeviceJoinTokenInput) (models.DeviceJoinToken, string, error) {
	store, ok := s.identityStore()
	if !ok {
		return models.DeviceJoinToken{}, "", models.ErrDevicesDisabled
	}
	maxUses, ttl, err := s.joinTokenLimits(in)
	if err != nil {
		return models.DeviceJoinToken{}, "", err
	}
	var raw, prefix string
	var hash []byte
	if in.Kind == JoinTokenKindClaim {
		if raw, err = generateClaimCode(); err != nil {
			return models.DeviceJoinToken{}, "", err
		}
		hash, _ = enrollmentTokenHash(raw)
		prefix = "claim"
	} else {
		secret, err := crypto.NewToken()
		if err != nil {
			return models.DeviceJoinToken{}, "", err
		}
		raw = joinTokenPrefix + secret
		hash, prefix = crypto.HashToken(raw), raw[:len(joinTokenPrefix)+4]
	}
	now := s.now().UTC()
	t := models.DeviceJoinToken{
		ID: ulid.New(), TokenHash: hash, Prefix: prefix,
		OrganizationID: in.OrganizationID, Name: in.Name, SPIFFEID: in.SPIFFEID,
		Scopes: append([]string(nil), in.Scopes...), CreatedBy: in.CreatedBy,
		CreatedAt: now, ExpiresAt: now.Add(ttl), MaxUses: maxUses,
	}
	if err := store.InsertDeviceJoinToken(ctx, t); err != nil {
		return models.DeviceJoinToken{}, "", err
	}
	s.Audit.EmitAudit(ctx, "device.join_token.created",
		models.TargetRef{Type: "device_join_token", ID: t.ID.String()},
		map[string]any{"name": t.Name, "spiffe_id": t.SPIFFEID, "expires_at": t.ExpiresAt.Format(time.RFC3339),
			"kind": in.Kind, "max_uses": maxUses})
	return t, raw, nil
}

// joinTokenLimits validates Kind, MaxUses and TTL and returns the values to store.
func (s *Service) joinTokenLimits(in CreateDeviceJoinTokenInput) (int, time.Duration, error) {
	if len(in.Scopes) == 0 || in.TTL < 0 {
		return 0, 0, models.ErrOAuthInvalidRequest
	}
	ttl := in.TTL
	var maxUses int
	switch in.Kind {
	case JoinTokenKindSingle, JoinTokenKindClaim:
		if in.MaxUses != 0 && in.MaxUses != 1 {
			return 0, 0, models.ErrOAuthInvalidRequest
		}
		maxUses = 1
	case JoinTokenKindBulk:
		// A SPIFFE ID is unique, so a token that fixes one can enroll one device only.
		if in.MaxUses < 1 || in.MaxUses > MaxDeviceBulkUses || (in.MaxUses > 1 && in.SPIFFEID != "") {
			return 0, 0, models.ErrOAuthInvalidRequest
		}
		maxUses = in.MaxUses
	default:
		return 0, 0, models.ErrOAuthInvalidRequest
	}
	if ttl == 0 {
		switch in.Kind {
		case JoinTokenKindClaim:
			ttl = DefaultDeviceClaimCodeTTL
		case JoinTokenKindBulk:
			ttl = DefaultDeviceBulkTokenTTL
		default:
			ttl = s.Cfg.DeviceTokens.JoinTokenTTL
		}
	}
	if in.Kind != JoinTokenKindSingle && ttl > MaxDeviceEnrollmentTTL {
		return 0, 0, models.ErrOAuthInvalidRequest
	}
	return maxUses, ttl, nil
}

// SuspendDevice puts an active device on hold: it gets no tokens until ResumeDevice. A non-nil
// orgID must own the device, else ErrStorageNotFound. A revoked device returns ErrDeviceRevoked.
// Suspending a suspended device succeeds.
func (s *Service) SuspendDevice(ctx context.Context, id models.ULID, orgID *models.ULID, actor *models.ULID) error {
	return s.changeDeviceStatus(ctx, id, orgID, actor, models.DeviceStatusSuspended)
}

// ResumeDevice lifts a suspension. A revoked device returns ErrDeviceRevoked, resuming an active
// device succeeds.
func (s *Service) ResumeDevice(ctx context.Context, id models.ULID, orgID *models.ULID, actor *models.ULID) error {
	return s.changeDeviceStatus(ctx, id, orgID, actor, models.DeviceStatusActive)
}

func (s *Service) changeDeviceStatus(ctx context.Context, id models.ULID, orgID, actor *models.ULID, to string) error {
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
	var changed bool
	event := "device.suspended"
	if to == models.DeviceStatusActive {
		event = "device.resumed"
		changed, err = store.ResumeDevice(ctx, id)
	} else {
		changed, err = store.SuspendDevice(ctx, id)
	}
	if err != nil {
		return err
	}
	if !changed {
		// Nothing moved: already in the wanted state is success, a revoked device is an error.
		cur, err := store.DeviceByID(ctx, id)
		if err != nil {
			return err
		}
		if cur.Status == models.DeviceStatusRevoked || cur.RevokedAt != nil {
			return models.ErrDeviceRevoked
		}
		s.notifyDeviceStatus(ctx, id, cur.Status)
		return nil
	}
	meta := map[string]any{"name": d.Name}
	if actor != nil {
		meta["by"] = actor.String()
	}
	s.Audit.EmitAudit(ctx, event, models.TargetRef{Type: "device", ID: id.String()}, meta)
	s.notifyDeviceStatus(ctx, id, to)
	return nil
}

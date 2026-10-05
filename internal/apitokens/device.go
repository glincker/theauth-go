package apitokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"slices"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// DeviceConfig tunes the RFC 8628 device authorization grant.
type DeviceConfig struct {
	// VerificationURI is the page where a signed-in user enters the user
	// code. Default: BaseURL + "/device".
	VerificationURI string
	// CodeTTL is how long a request stays approvable. Default 10 minutes.
	CodeTTL time.Duration
	// Interval is the minimum polling gap. Default 5 seconds.
	Interval time.Duration
	// TokenTTL is the lifetime of a minted token. Default 30 days.
	TokenTTL time.Duration
	// DefaultAbilities apply when the client requests none. With none
	// configured, a request must name its abilities.
	DefaultAbilities []string
}

func (c DeviceConfig) withDefaults(baseURL string) DeviceConfig {
	if c.VerificationURI == "" {
		c.VerificationURI = strings.TrimRight(baseURL, "/") + "/device"
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = 10 * time.Minute
	}
	if c.Interval <= 0 {
		c.Interval = 5 * time.Second
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = 30 * 24 * time.Hour
	}
	return c
}

// Errors returned by the device grant, named after their RFC 8628 error codes.
var (
	ErrDeviceDisabled             = errors.New("theauth: device authorization is not enabled in Config")
	ErrDeviceAuthorizationPending = errors.New("theauth: authorization_pending")
	ErrDeviceSlowDown             = errors.New("theauth: slow_down")
	ErrDeviceExpired              = errors.New("theauth: expired_token")
	ErrDeviceDenied               = errors.New("theauth: access_denied")
	ErrDeviceInvalid              = errors.New("theauth: invalid device or user code")
	ErrDeviceAttemptsExceeded     = errors.New("theauth: too many failed user code attempts")
)

// userCodeAlphabet omits vowels and look-alikes (0, 1, 2, 5, L, S, Z) so codes read aloud and copy cleanly.
const (
	userCodeAlphabet = "BCDFGHJKMNPQRTVWXY346789"
	userCodeLen      = 8
	slowDownStep     = 5
)

func newUserCode() (string, error) {
	out := make([]byte, 0, userCodeLen)
	limit := 256 - 256%len(userCodeAlphabet)
	buf := make([]byte, 16)
	for len(out) < userCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("theauth: generate user code: %w", err)
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < userCodeLen {
				out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
			}
		}
	}
	return string(out), nil
}

// FormatUserCode renders a user code as XXXX-XXXX for display.
func FormatUserCode(code string) string {
	if len(code) != userCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

func normalizeUserCode(in string) string {
	in = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(in)))
	return in
}

// DeviceAuthStart is the response to a device authorization request.
type DeviceAuthStart struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	Interval                time.Duration
}

// StartDeviceAuthInput carries the requester's details. Abilities may be empty
// when DeviceConfig.DefaultAbilities is set.
type StartDeviceAuthInput struct {
	ClientName string
	Abilities  []string
	IP         string
	UserAgent  string
}

// StartDeviceAuth opens a device authorization request.
func (s *Service) StartDeviceAuth(ctx context.Context, in StartDeviceAuthInput) (DeviceAuthStart, error) {
	if s.dev == nil {
		return DeviceAuthStart{}, ErrDeviceDisabled
	}
	dc := s.cfg.Device
	abilities := in.Abilities
	if len(abilities) == 0 {
		abilities = dc.DefaultAbilities
	}
	if err := s.validateAbilities(abilities, false); err != nil {
		return DeviceAuthStart{}, err
	}
	client := strings.TrimSpace(in.ClientName)
	if len(client) > 120 {
		client = client[:120]
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return DeviceAuthStart{}, fmt.Errorf("theauth: generate device code: %w", err)
	}
	deviceCode := base64.RawURLEncoding.EncodeToString(secret)
	now := s.now().UTC()
	for range 5 {
		uc, err := newUserCode()
		if err != nil {
			return DeviceAuthStart{}, err
		}
		rec := DeviceCode{
			ID: ulid.New(), DeviceCodeHash: hashToken(deviceCode), UserCode: uc, Status: DeviceStatusPending,
			ClientName: client, RequestedAbilities: slices.Clone(abilities), RequesterIP: in.IP, RequesterUA: in.UserAgent,
			IntervalSeconds: int(dc.Interval / time.Second), CreatedAt: now, ExpiresAt: now.Add(dc.CodeTTL),
		}
		err = s.dev.InsertDeviceCode(ctx, rec)
		if errors.Is(err, ErrDeviceUserCodeTaken) {
			continue
		}
		if err != nil {
			return DeviceAuthStart{}, fmt.Errorf("theauth: store device code: %w", err)
		}
		return DeviceAuthStart{
			DeviceCode: deviceCode, UserCode: FormatUserCode(uc), VerificationURI: dc.VerificationURI,
			VerificationURIComplete: dc.VerificationURI + "?user_code=" + FormatUserCode(uc),
			ExpiresIn:               dc.CodeTTL, Interval: dc.Interval,
		}, nil
	}
	return DeviceAuthStart{}, errors.New("theauth: could not allocate a unique user code")
}

// DeviceRequestInfo is what an approver sees before deciding.
type DeviceRequestInfo struct {
	ClientName         string
	RequestedAbilities []string
	RequesterIP        string
	RequesterUserAgent string
	ExpiresAt          time.Time
}

// LookupDeviceRequest returns the pending request behind a user code so the
// approver can review it. Failed lookups count against a per-approver budget
// (ErrDeviceAttemptsExceeded once spent).
func (s *Service) LookupDeviceRequest(ctx context.Context, approver *User, ip, userCode string) (*DeviceRequestInfo, error) {
	if s.dev == nil {
		return nil, ErrDeviceDisabled
	}
	rec, err := s.lookupPending(ctx, approver, ip, userCode)
	if err != nil {
		return nil, err
	}
	return &DeviceRequestInfo{rec.ClientName, slices.Clone(rec.RequestedAbilities), rec.RequesterIP, rec.RequesterUA, rec.ExpiresAt}, nil
}

func (s *Service) lookupPending(ctx context.Context, approver *User, ip, userCode string) (*DeviceCode, error) {
	now := s.now()
	keys := []string{"u:" + approver.ID.String(), "ip:" + ip}
	for _, k := range keys {
		if s.fails.blocked(k, now) {
			return nil, ErrDeviceAttemptsExceeded
		}
	}
	rec, err := s.dev.DeviceCodeByUserCode(ctx, normalizeUserCode(userCode))
	if errors.Is(err, models.ErrStorageNotFound) {
		for _, k := range keys {
			s.fails.fail(k, now)
		}
		return nil, ErrDeviceInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("theauth: look up device code: %w", err)
	}
	if !now.Before(rec.ExpiresAt) {
		return nil, ErrDeviceExpired
	}
	if rec.Status != DeviceStatusPending {
		return nil, ErrDeviceInvalid
	}
	return rec, nil
}

// DecideDeviceRequest approves or denies a pending request as approver. On
// approval the abilities are the requested set (or the narrower subset in
// abilities) capped to what the approver holds now. Root is granted only when
// requested and the approver holds root; it is never downgraded silently.
func (s *Service) DecideDeviceRequest(ctx context.Context, approver *User, ip, userCode string, approve bool, abilities []string) error {
	if s.dev == nil {
		return ErrDeviceDisabled
	}
	rec, err := s.lookupPending(ctx, approver, ip, userCode)
	if err != nil {
		return err
	}
	return s.decideRecord(ctx, approver, rec, approve, abilities)
}

func (s *Service) decideRecord(ctx context.Context, approver *User, rec *DeviceCode, approve bool, abilities []string) error {
	d := DeviceDecision{Approve: approve, ApproverID: approver.ID}
	if approve {
		chosen := rec.RequestedAbilities
		if len(abilities) > 0 {
			for _, ab := range abilities {
				if !slices.Contains(rec.RequestedAbilities, ab) {
					return fmt.Errorf("%w: %q was not requested", ErrAbilityInvalid, ab)
				}
			}
			chosen = abilities
		}
		held, err := s.UserAbilities(ctx, approver)
		if err != nil {
			return fmt.Errorf("theauth: resolve approver abilities: %w", err)
		}
		if slices.Contains(chosen, AbilityRoot) && !slices.Contains(held, AbilityRoot) {
			return ErrAbilityNotHeld
		}
		d.Abilities = clampAbilities(chosen, held)
		if len(d.Abilities) == 0 {
			return ErrAbilityNotHeld
		}
	}
	err := s.dev.DecideDeviceCode(ctx, rec.UserCode, d, s.now().UTC())
	if errors.Is(err, models.ErrStorageNotFound) {
		return ErrDeviceExpired
	}
	if err != nil {
		return fmt.Errorf("theauth: record device decision: %w", err)
	}
	return nil
}

// DeviceToken is a token minted by a completed device grant.
type DeviceToken struct {
	Token     string
	APIToken  APIToken
	ExpiresIn time.Duration
}

// RedeemDeviceCode exchanges an approved device code for a token. The
// approved to redeemed transition is one atomic claim, so concurrent polls
// mint at most one token. Polling faster than the interval returns
// ErrDeviceSlowDown and widens the interval.
func (s *Service) RedeemDeviceCode(ctx context.Context, deviceCode string) (DeviceToken, error) {
	if s.dev == nil {
		return DeviceToken{}, ErrDeviceDisabled
	}
	hash := hashToken(deviceCode)
	rec, err := s.dev.DeviceCodeByHash(ctx, hash)
	if errors.Is(err, models.ErrStorageNotFound) {
		return DeviceToken{}, ErrDeviceInvalid
	}
	if err != nil {
		return DeviceToken{}, fmt.Errorf("theauth: look up device code: %w", err)
	}
	now := s.now().UTC()
	if !now.Before(rec.ExpiresAt) {
		return DeviceToken{}, ErrDeviceExpired
	}
	if rec.LastPolledAt != nil && now.Sub(*rec.LastPolledAt) < time.Duration(rec.IntervalSeconds)*time.Second {
		next := rec.IntervalSeconds + slowDownStep
		if err := s.dev.RecordDevicePoll(ctx, hash, now, next); err != nil {
			return DeviceToken{}, fmt.Errorf("theauth: record device poll: %w", err)
		}
		return DeviceToken{}, ErrDeviceSlowDown
	}
	if err := s.dev.RecordDevicePoll(ctx, hash, now, rec.IntervalSeconds); err != nil {
		return DeviceToken{}, fmt.Errorf("theauth: record device poll: %w", err)
	}
	switch rec.Status {
	case DeviceStatusPending:
		return DeviceToken{}, ErrDeviceAuthorizationPending
	case DeviceStatusDenied:
		return DeviceToken{}, ErrDeviceDenied
	case DeviceStatusRedeemed:
		return DeviceToken{}, ErrDeviceInvalid
	}
	claimed, err := s.dev.ClaimDeviceCode(ctx, hash, now)
	if errors.Is(err, models.ErrStorageNotFound) {
		return DeviceToken{}, ErrDeviceInvalid
	}
	if err != nil {
		return DeviceToken{}, fmt.Errorf("theauth: claim device code: %w", err)
	}
	if claimed.ApproverID == nil {
		return DeviceToken{}, ErrDeviceInvalid
	}
	if _, active, err := s.ownerActive(ctx, OwnerKindUser, *claimed.ApproverID); err != nil || !active {
		if err != nil {
			return DeviceToken{}, err
		}
		return DeviceToken{}, ErrDeviceDenied
	}
	name := "device login"
	if claimed.ClientName != "" {
		name = "device: " + claimed.ClientName
	}
	raw, tok, err := s.Mint(ctx, MintAPITokenInput{
		OwnerID: *claimed.ApproverID, OwnerKind: OwnerKindUser, Name: name,
		Abilities: claimed.ApprovedAbilities, TTL: s.cfg.Device.TokenTTL,
	})
	if err != nil {
		return DeviceToken{}, fmt.Errorf("theauth: mint device token: %w", err)
	}
	return DeviceToken{Token: raw, APIToken: tok, ExpiresIn: s.cfg.Device.TokenTTL}, nil
}

// PurgeExpiredDeviceCodes deletes requests that expired before the cutoff.
func (s *Service) PurgeExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error) {
	if s.dev == nil {
		return 0, ErrDeviceDisabled
	}
	return s.dev.DeleteExpiredDeviceCodes(ctx, before)
}

// DeviceRequestSummary is one pending request as a dashboard lists it. It
// carries the request ID instead of any code.
type DeviceRequestSummary struct {
	ID                 ULID      `json:"id"`
	ClientName         string    `json:"clientName"`
	RequestedAbilities []string  `json:"requestedAbilities"`
	RequesterIP        string    `json:"requesterIp"`
	RequesterUserAgent string    `json:"requesterUserAgent"`
	CreatedAt          time.Time `json:"createdAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
}

// ErrDeviceListUnsupported is returned when the storage lacks DeviceCodeLister.
var ErrDeviceListUnsupported = errors.New("theauth: storage does not implement DeviceCodeLister")

func (s *Service) listPending(ctx context.Context) ([]DeviceCode, error) {
	l, ok := s.dev.(DeviceCodeLister)
	if !ok {
		return nil, ErrDeviceListUnsupported
	}
	recs, err := l.ListPendingDeviceCodes(ctx, DevicePendingFilter{Now: s.now().UTC(), Limit: 500})
	if err != nil {
		return nil, fmt.Errorf("theauth: list pending device codes: %w", err)
	}
	return recs, nil
}

// ListDeviceRequests returns the pending, unexpired device requests, newest
// first, without any device or user code.
func (s *Service) ListDeviceRequests(ctx context.Context) ([]DeviceRequestSummary, error) {
	if s.dev == nil {
		return nil, ErrDeviceDisabled
	}
	recs, err := s.listPending(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceRequestSummary, 0, len(recs))
	for _, r := range recs {
		out = append(out, DeviceRequestSummary{
			ID: r.ID, ClientName: r.ClientName, RequestedAbilities: slices.Clone(r.RequestedAbilities),
			RequesterIP: r.RequesterIP, RequesterUserAgent: r.RequesterUA, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		})
	}
	return out, nil
}

// DecideDeviceRequestByID approves or denies a pending request by its ID with
// the same rules as DecideDeviceRequest. An unknown, expired or already
// decided ID returns ErrDeviceInvalid or ErrDeviceExpired.
func (s *Service) DecideDeviceRequestByID(ctx context.Context, approver *User, id ULID, approve bool, abilities []string) error {
	if s.dev == nil {
		return ErrDeviceDisabled
	}
	recs, err := s.listPending(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(recs, func(r DeviceCode) bool { return r.ID == id })
	if i < 0 {
		return ErrDeviceInvalid
	}
	if err := s.decideRecord(ctx, approver, &recs[i], approve, abilities); err != nil {
		return err
	}
	action := "device.denied"
	if approve {
		action = "device.approved"
	}
	s.host.EmitAudit(ctx, action, models.TargetRef{Type: "device_request", ID: id.String()}, map[string]any{"approver": approver.ID.String()})
	return nil
}

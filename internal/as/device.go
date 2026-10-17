package as

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// device.go implements the RFC 8628 device grant: device authorization, the user-code verification
// page, and the device_code arm of the token endpoint. device_code and user_code are stored only as
// keyed HMACs, so a database leak exposes no live codes. A device_code redeems once (conditional
// approved to consumed update), the verification page needs a signed-in user and rate limits
// attempts, and polling too fast returns slow_down (RFC 8628 section 3.5).

const (
	// DefaultDeviceExpiry is the device_code lifetime.
	DefaultDeviceExpiry = 10 * time.Minute
	// DefaultDeviceInterval is the minimum polling interval.
	DefaultDeviceInterval = 5 * time.Second
	// DefaultUserCodeAlphabet omits vowels and look-alike characters (RFC 8628 section 6.1).
	DefaultUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// DefaultUserCodeLength is the number of symbols, ~34.5 bits.
	DefaultUserCodeLength       = 8
	DefaultDeviceVerifyAttempts = 10
	// DefaultDeviceVerifyWindow is that window.
	DefaultDeviceVerifyWindow = 15 * time.Minute

	deviceSlowDownStep = 5
	deviceMaxInsertTry = 5
)

// DeviceConfig enables and tunes the device grant. Zero fields take the defaults above.
type DeviceConfig struct {
	// VerificationURI is the page users open (default Issuer plus /oauth/device). Set it to a vanity
	// URL if you proxy the page.
	VerificationURI string

	ExpiresIn time.Duration

	Interval time.Duration

	// UserCodeLength and UserCodeAlphabet shape the typed code. Alphabets under 16 symbols or lengths
	// under 6 are rejected.
	UserCodeLength   int
	UserCodeAlphabet string

	// MaxVerifyAttempts caps user-code submissions per subject (signed-in user, else client IP) per
	// VerifyAttemptWindow.
	MaxVerifyAttempts   int
	VerifyAttemptWindow time.Duration

	// Page, when set, renders the verification page instead of the built-in HTML.
	Page func(w http.ResponseWriter, r *http.Request, p DevicePage)

	// CSS is appended to the built-in page. It is trusted operator input and is not escaped.
	CSS string
}

func applyDeviceDefaults(c *DeviceConfig) {
	if c.ExpiresIn <= 0 {
		c.ExpiresIn = DefaultDeviceExpiry
	}
	if c.Interval <= 0 {
		c.Interval = DefaultDeviceInterval
	}
	if c.UserCodeAlphabet == "" {
		c.UserCodeAlphabet = DefaultUserCodeAlphabet
	}
	if c.UserCodeLength <= 0 {
		c.UserCodeLength = DefaultUserCodeLength
	}
	if c.MaxVerifyAttempts <= 0 {
		c.MaxVerifyAttempts = DefaultDeviceVerifyAttempts
	}
	if c.VerifyAttemptWindow <= 0 {
		c.VerifyAttemptWindow = DefaultDeviceVerifyWindow
	}
}

// DeviceAuthRequest is the parsed body of POST /oauth/device_authorization.
type DeviceAuthRequest struct {
	ClientID     string
	ClientSecret string
	Scope        []string
	Resource     string
}

// DeviceAuthResponse is the RFC 8628 section 3.2 response body.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceTokenRequest is the device_code arm of POST /oauth/token. TokenRequest carries the client
// credentials and DPoP proof.
type DeviceTokenRequest struct {
	TokenRequest
	DeviceCode string
}

const (
	DevicePageEnter   = "enter"
	DevicePageConfirm = "confirm"
	DevicePageDone    = "done"
	DevicePageError   = "error"
)

// DevicePage is the view model for the verification page.
type DevicePage struct {
	State    string
	UserCode string
	Pending  *DevicePending
	Approved bool
	Error    string
	Action   string
	CSS      string
}

// DevicePending describes a pending authorization to the signed-in user, so they can see what they approve.
type DevicePending struct {
	ClientID   string
	ClientName string
	Scope      []string
	ExpiresAt  time.Time
}

func (s *Service) deviceStore() (DeviceAuthorizationStorage, bool) {
	if s == nil || s.Cfg.DeviceAuthorization == nil {
		return nil, false
	}
	st, ok := s.Storage.(DeviceAuthorizationStorage)
	return st, ok
}

// IsDeviceEnabled reports whether the device grant is configured and the storage supports it.
func (s *Service) IsDeviceEnabled() bool {
	_, ok := s.deviceStore()
	return ok
}

// DeviceVerificationURI is the page users are sent to.
func (s *Service) DeviceVerificationURI() string {
	if s.Cfg.DeviceAuthorization != nil && s.Cfg.DeviceAuthorization.VerificationURI != "" {
		return s.Cfg.DeviceAuthorization.VerificationURI
	}
	return s.Cfg.Issuer + "/oauth/device"
}

// codeHash returns the keyed hash stored for a device or user code. The label separates the two code spaces.
func (s *Service) codeHash(label, code string) []byte {
	sub := hmac.New(sha256.New, s.encryptionKey)
	sub.Write([]byte("theauth/device-authorization/v1"))
	mac := hmac.New(sha256.New, sub.Sum(nil))
	mac.Write([]byte(label))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

// normalizeUserCode upper-cases the input and drops separators and characters outside the alphabet.
func normalizeUserCode(in, alphabet string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(in) {
		if strings.ContainsRune(alphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatUserCode(code string) string {
	if len(code) < 4 {
		return code
	}
	h := len(code) / 2
	return code[:h] + "-" + code[h:]
}

func newUserCode(alphabet string, n int) (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	var b strings.Builder
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[v.Int64()])
	}
	return b.String(), nil
}

func newDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) now() time.Time { return s.Cfg.Clock.Now() }

// StartDeviceAuthorization handles POST /oauth/device_authorization.
func (s *Service) StartDeviceAuthorization(ctx context.Context, req DeviceAuthRequest) (DeviceAuthResponse, error) {
	store, ok := s.deviceStore()
	if !ok {
		return DeviceAuthResponse{}, models.ErrDeviceAuthDisabled
	}
	cfg := s.Cfg.DeviceAuthorization
	client, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	if !containsString(client.GrantTypes, models.GrantTypeDeviceCode) {
		return DeviceAuthResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	resource, err := s.deviceResource(req.Resource)
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	scope, err := validateScopeAgainstResource(req.Scope, resource)
	if err != nil {
		if len(req.Scope) == 0 {
			return DeviceAuthResponse{}, models.ErrOAuthInvalidScope
		}
		return DeviceAuthResponse{}, err
	}

	deviceCode, err := newDeviceCode()
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	now := s.now()
	row := models.DeviceAuthorization{
		ID:              ulid.New(),
		DeviceCodeHash:  s.codeHash("device", deviceCode),
		ClientID:        client.ClientID,
		Scope:           scope,
		Resource:        resource.Identifier,
		Status:          models.DeviceAuthPending,
		IntervalSeconds: int(cfg.Interval.Seconds()),
		CreatedAt:       now,
		ExpiresAt:       now.Add(cfg.ExpiresIn),
	}
	var userCode string
	for try := 0; ; try++ {
		if try >= deviceMaxInsertTry {
			return DeviceAuthResponse{}, errors.New("theauth: could not allocate a unique user code")
		}
		userCode, err = newUserCode(cfg.UserCodeAlphabet, cfg.UserCodeLength)
		if err != nil {
			return DeviceAuthResponse{}, err
		}
		row.UserCodeHash = s.codeHash("user", userCode)
		err = store.InsertDeviceAuthorization(ctx, row)
		if errors.Is(err, models.ErrDeviceAuthUserCodeTaken) {
			continue
		}
		if err != nil {
			return DeviceAuthResponse{}, err
		}
		break
	}
	s.Audit.EmitAudit(ctx, "oauth.device.requested",
		models.TargetRef{Type: "oauth_client", ID: client.ClientID},
		map[string]any{"scope": scopeJoin(scope), "resource": resource.Identifier})

	display := formatUserCode(userCode)
	base := s.DeviceVerificationURI()
	return DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                display,
		VerificationURI:         base,
		VerificationURIComplete: base + sepFor(base) + "user_code=" + url.QueryEscape(display),
		ExpiresIn:               int(cfg.ExpiresIn.Seconds()),
		Interval:                row.IntervalSeconds,
	}, nil
}

func sepFor(u string) string {
	if strings.Contains(u, "?") {
		return "&"
	}
	return "?"
}

// deviceResource resolves the requested audience. An empty request maps to the only configured
// resource, and is required when several are configured.
func (s *Service) deviceResource(id string) (models.ProtectedResource, error) {
	if id == "" {
		if len(s.Cfg.Resources) == 1 {
			return s.Cfg.Resources[0], nil
		}
		return models.ProtectedResource{}, models.ErrOAuthInvalidResource
	}
	r, ok := s.ResourceByIdentifier(id)
	if !ok {
		return models.ProtectedResource{}, models.ErrOAuthInvalidResource
	}
	return r, nil
}

func (s *Service) attemptAllowed(ctx context.Context, subject string) error {
	cfg := s.Cfg.DeviceAuthorization
	d, err := s.Limiter.Allow(ctx, "device:verify:"+subject, cfg.MaxVerifyAttempts, cfg.VerifyAttemptWindow)
	if err != nil {
		// A broken limiter must not become an open guessing oracle, so it fails closed.
		return fmt.Errorf("theauth: device attempt limiter: %w", err)
	}
	if !d.Allowed {
		return models.ErrDeviceTooManyAttempts
	}
	return nil
}

func (s *Service) lookupPending(ctx context.Context, store DeviceAuthorizationStorage, userCode string) (*models.DeviceAuthorization, error) {
	cfg := s.Cfg.DeviceAuthorization
	norm := normalizeUserCode(userCode, cfg.UserCodeAlphabet)
	if len(norm) != cfg.UserCodeLength {
		return nil, models.ErrDeviceUserCodeInvalid
	}
	row, err := store.DeviceAuthorizationByUserCodeHash(ctx, s.codeHash("user", norm))
	if err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return nil, models.ErrDeviceUserCodeInvalid
		}
		return nil, err
	}
	if row.Status != models.DeviceAuthPending || !s.now().Before(row.ExpiresAt) {
		return nil, models.ErrDeviceUserCodeInvalid
	}
	return row, nil
}

// LookupDeviceUserCode resolves a typed user code to the request the signed-in user is about to approve.
func (s *Service) LookupDeviceUserCode(ctx context.Context, subject, userCode string) (DevicePending, error) {
	store, ok := s.deviceStore()
	if !ok {
		return DevicePending{}, models.ErrDeviceAuthDisabled
	}
	if err := s.attemptAllowed(ctx, subject); err != nil {
		return DevicePending{}, err
	}
	row, err := s.lookupPending(ctx, store, userCode)
	if err != nil {
		return DevicePending{}, err
	}
	name := row.ClientID
	if c, cerr := s.ResolveClient(ctx, row.ClientID); cerr == nil && c.ClientName != "" {
		name = c.ClientName
	}
	return DevicePending{ClientID: row.ClientID, ClientName: name, Scope: row.Scope, ExpiresAt: row.ExpiresAt}, nil
}

// DecideDeviceUserCode records the signed-in user's approval or denial.
func (s *Service) DecideDeviceUserCode(ctx context.Context, subject, userCode string, userID models.ULID, approve bool) error {
	store, ok := s.deviceStore()
	if !ok {
		return models.ErrDeviceAuthDisabled
	}
	if err := s.attemptAllowed(ctx, subject); err != nil {
		return err
	}
	row, err := s.lookupPending(ctx, store, userCode)
	if err != nil {
		return err
	}
	status, action := models.DeviceAuthDenied, "oauth.device.denied"
	if approve {
		status, action = models.DeviceAuthApproved, "oauth.device.approved"
	}
	applied, err := store.DecideDeviceAuthorization(ctx, row.ID, status, userID, s.now())
	if err != nil {
		return err
	}
	if !applied {
		return models.ErrDeviceUserCodeInvalid
	}
	s.Audit.EmitAudit(ctx, action,
		models.TargetRef{Type: "oauth_client", ID: row.ClientID},
		map[string]any{"user_id": userID.String(), "scope": scopeJoin(row.Scope)})
	return nil
}

// PollDeviceToken handles the device_code grant at POST /oauth/token.
func (s *Service) PollDeviceToken(ctx context.Context, req DeviceTokenRequest) (TokenResponse, error) {
	store, ok := s.deviceStore()
	if !ok {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	client, err := s.AuthenticateClientFromRequest(ctx, req.TokenRequest, s.tokenEndpointURL())
	if err != nil {
		return TokenResponse{}, err
	}
	if req.DeviceCode == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	row, err := store.DeviceAuthorizationByDeviceCodeHash(ctx, s.codeHash("device", req.DeviceCode))
	if err != nil {
		if errors.Is(err, models.ErrStorageNotFound) {
			return TokenResponse{}, models.ErrOAuthInvalidGrant
		}
		return TokenResponse{}, err
	}
	if row.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	now := s.now()
	if !now.Before(row.ExpiresAt) {
		return TokenResponse{}, models.ErrDeviceExpiredToken
	}

	interval := row.IntervalSeconds
	tooFast := row.LastPollAt != nil && now.Sub(*row.LastPollAt) < time.Duration(interval)*time.Second
	if tooFast {
		interval += deviceSlowDownStep
	}
	if err := store.RecordDeviceAuthorizationPoll(ctx, row.ID, now, interval); err != nil {
		return TokenResponse{}, err
	}
	if tooFast {
		return TokenResponse{}, models.ErrDeviceSlowDown
	}

	switch row.Status {
	case models.DeviceAuthPending:
		return TokenResponse{}, models.ErrDeviceAuthorizationPending
	case models.DeviceAuthDenied:
		return TokenResponse{}, models.ErrDeviceAccessDenied
	case models.DeviceAuthApproved:
	default:
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	if row.UserID == nil {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// The DPoP proof is verified before the single-use record is spent, so a bad proof does not burn
	// an approval.
	jkt, err := s.dpopThumbprintForRequest(req.TokenRequest)
	if err != nil {
		return TokenResponse{}, err
	}
	won, err := store.ConsumeDeviceAuthorization(ctx, row.ID, now)
	if err != nil {
		return TokenResponse{}, err
	}
	if !won {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	resp, err := s.mintAccessAndRefresh(ctx, mintInput{
		ClientID: client.ClientID,
		UserID:   row.UserID,
		Scope:    row.Scope,
		Resource: row.Resource,
		DPoPJKT:  jkt,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	s.Audit.EmitAudit(ctx, "oauth.device.redeemed",
		models.TargetRef{Type: "oauth_client", ID: client.ClientID},
		map[string]any{"user_id": row.UserID.String()})
	return resp, nil
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

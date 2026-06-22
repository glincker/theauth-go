package as

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// ciba.go: CIBA (RFC 9509) backchannel authentication service logic.
// Endpoints: POST /oauth/bc-authorize, plus the CIBA grant arm of
// POST /oauth/token. User decision paths (approve/deny) are exported
// as TheAuth methods in service_ciba.go at the root level.

// BackchannelAuthRequest is the parsed form body of POST /oauth/bc-authorize.
type BackchannelAuthRequest struct {
	// ClientID + ClientSecret authenticate the requesting client.
	ClientID     string
	ClientSecret string

	// One of LoginHint, LoginHintToken, or IDTokenHint MUST be present.
	LoginHint      string
	LoginHintToken string
	IDTokenHint    string

	// Scope is the requested scope list (space-separated on the wire).
	Scope []string

	// BindingMessage is an optional short string shown on the AD.
	BindingMessage string

	// ClientNotificationToken is the bearer token for Ping mode callbacks.
	// Empty for Poll mode.
	ClientNotificationToken string

	// RequestedExpiry, when > 0, overrides the server default (capped at
	// CIBAConfig.MaxRequestedExpiry).
	RequestedExpiry int
}

// BackchannelAuthResponse is returned from POST /oauth/bc-authorize on
// success.
type BackchannelAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// CIBATokenRequest is the CIBA arm of TokenRequest: grant_type =
// urn:openid:params:grant-type:ciba plus the auth_req_id polling handle.
type CIBATokenRequest struct {
	ClientID     string
	ClientSecret string
	AuthReqID    string
}

// BackchannelAuthenticate processes POST /oauth/bc-authorize. It:
//  1. Authenticates the client.
//  2. Validates that exactly one hint is present.
//  3. Generates a 256-bit auth_req_id.
//  4. Persists the BackchannelRequest row.
//  5. Calls AuthenticationDevice.Notify to alert the user's device.
//
// Returns ErrCIBADisabled when CIBA is not configured or the storage does not
// implement CIBAStorage.
func (s *Service) BackchannelAuthenticate(ctx context.Context, req BackchannelAuthRequest) (BackchannelAuthResponse, error) {
	if s == nil || s.Cfg.CIBA == nil {
		return BackchannelAuthResponse{}, models.ErrCIBADisabled
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return BackchannelAuthResponse{}, models.ErrCIBADisabled
	}

	// Authenticate the client.
	_, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return BackchannelAuthResponse{}, err
	}

	// Exactly one hint MUST be present (RFC 9509 section 7.1).
	hintCount := 0
	if req.LoginHint != "" {
		hintCount++
	}
	if req.LoginHintToken != "" {
		hintCount++
	}
	if req.IDTokenHint != "" {
		hintCount++
	}
	if hintCount != 1 {
		return BackchannelAuthResponse{}, models.ErrCIBAInvalidRequest
	}

	// Scope is required.
	if len(req.Scope) == 0 {
		return BackchannelAuthResponse{}, models.ErrCIBAInvalidRequest
	}

	// Resolve expiry.
	cfg := s.Cfg.CIBA
	expiry := cfg.DefaultExpiry
	if req.RequestedExpiry > 0 {
		requested := time.Duration(req.RequestedExpiry) * time.Second
		if requested < expiry {
			expiry = requested
		}
		if expiry > cfg.MaxRequestedExpiry {
			expiry = cfg.MaxRequestedExpiry
		}
	}

	// Generate auth_req_id: 32 bytes = 256 bits, base64url-encoded.
	authReqID, err := generateAuthReqID()
	if err != nil {
		return BackchannelAuthResponse{}, err
	}

	now := time.Now()
	row := models.BackchannelRequest{
		AuthReqID:               authReqID,
		ClientID:                req.ClientID,
		LoginHint:               req.LoginHint,
		LoginHintToken:          req.LoginHintToken,
		IDTokenHint:             req.IDTokenHint,
		Scope:                   append([]string(nil), req.Scope...),
		BindingMessage:          req.BindingMessage,
		ClientNotificationToken: req.ClientNotificationToken,
		Status:                  models.BackchannelStatusPending,
		PollInterval:            int(cfg.DefaultInterval.Seconds()),
		ExpiresAt:               now.Add(expiry),
		CreatedAt:               now,
	}

	if err := cibaStore.InsertBackchannelRequest(ctx, row); err != nil {
		return BackchannelAuthResponse{}, err
	}

	// Notify the Authentication Device. The hint that identifies the user
	// is forwarded so the operator can resolve it to an actual user identity.
	userHint := req.LoginHint
	if userHint == "" {
		userHint = req.LoginHintToken
	}
	if userHint == "" {
		userHint = req.IDTokenHint
	}

	note := CIBANotification{
		AuthReqID:      authReqID,
		UserID:         userHint,
		ClientID:       req.ClientID,
		Scopes:         append([]string(nil), req.Scope...),
		BindingMessage: req.BindingMessage,
		ExpiresAt:      row.ExpiresAt,
	}
	if err := cfg.AuthenticationDevice.Notify(ctx, note); err != nil {
		// Notify failure is non-fatal at the storage level; the row is
		// already persisted. Return a service unavailable signal so the
		// client knows the push failed.
		return BackchannelAuthResponse{}, &cibaNotifyError{inner: err}
	}

	return BackchannelAuthResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(expiry.Seconds()),
		Interval:  int(cfg.DefaultInterval.Seconds()),
	}, nil
}

// PollBackchannelToken handles the CIBA arm of POST /oauth/token. It:
//  1. Authenticates the client.
//  2. Loads the BackchannelRequest row.
//  3. Checks expiry, status, and poll rate.
//  4. Returns the token response when approved, or the appropriate pending
//     error.
func (s *Service) PollBackchannelToken(ctx context.Context, req CIBATokenRequest) (TokenResponse, error) {
	if s == nil || s.Cfg.CIBA == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}

	// Authenticate the client.
	client, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}

	if req.AuthReqID == "" {
		return TokenResponse{}, models.ErrCIBAInvalidRequest
	}

	now := time.Now()

	// Touch poll timestamp and enforce slow_down before reading status.
	cfg := s.Cfg.CIBA
	row, err := cibaStore.BackchannelRequestByID(ctx, req.AuthReqID)
	if err != nil {
		// Missing row is an invalid_grant (auth_req_id unknown or already
		// cleaned up).
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}

	// Verify the polling client owns this request.
	if row.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}

	// Check expiry first.
	if !now.Before(row.ExpiresAt) {
		return TokenResponse{}, models.ErrCIBAExpiredToken
	}

	// Enforce minimum poll interval (slow_down check).
	// MinPollInterval is the absolute server-side floor; PollInterval is the
	// recommendation advertised to the client. slow_down fires only when the
	// client polls faster than the absolute floor.
	if row.LastPollAt != nil {
		elapsed := now.Sub(*row.LastPollAt)
		if elapsed < cfg.MinPollInterval {
			// Double the interval (capped at MaxRequestedExpiry to avoid
			// pathological growth) and record the new interval.
			newInterval := row.PollInterval * 2
			maxSeconds := int(cfg.MaxRequestedExpiry.Seconds())
			if newInterval > maxSeconds {
				newInterval = maxSeconds
			}
			_, touchErr := cibaStore.TouchBackchannelPoll(ctx, req.AuthReqID, now, newInterval)
			if touchErr != nil {
				return TokenResponse{}, touchErr
			}
			return TokenResponse{}, models.ErrCIBASlowDown
		}
	}

	// Record the poll time.
	row, err = cibaStore.TouchBackchannelPoll(ctx, req.AuthReqID, now, row.PollInterval)
	if err != nil {
		return TokenResponse{}, err
	}

	// Dispatch on status.
	switch row.Status {
	case models.BackchannelStatusPending:
		return TokenResponse{}, models.ErrCIBAAuthorizationPending
	case models.BackchannelStatusDenied:
		return TokenResponse{}, models.ErrCIBAAccessDenied
	case models.BackchannelStatusApproved:
		if row.AccessToken == "" {
			// Approved row should always have a token; storage inconsistency.
			return TokenResponse{}, models.ErrCIBAAuthorizationPending
		}
		return TokenResponse{
			AccessToken:  row.AccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(s.Cfg.AccessTokenTTL.Seconds()),
			RefreshToken: row.RefreshToken,
			Scope:        scopeJoin(row.Scope),
		}, nil
	default:
		return TokenResponse{}, models.ErrCIBAAuthorizationPending
	}
}

// ApproveBackchannelRequest is the service-layer operation called when the
// operator's AD callback confirms user approval. It:
//  1. Loads the pending request.
//  2. Verifies userID matches the login_hint when a userID was set.
//  3. Mints access + refresh tokens.
//  4. Persists status = approved with the token strings.
//
// This method is exposed to operators via TheAuth.ApproveBackchannelAuth.
func (s *Service) ApproveBackchannelRequest(ctx context.Context, authReqID string, userID models.ULID) error {
	if s == nil || s.Cfg.CIBA == nil {
		return models.ErrCIBADisabled
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return models.ErrCIBADisabled
	}

	row, err := cibaStore.BackchannelRequestByID(ctx, authReqID)
	if err != nil {
		return models.ErrOAuthInvalidGrant
	}
	if row.Status != models.BackchannelStatusPending {
		return models.ErrOAuthInvalidGrant
	}
	if !time.Now().Before(row.ExpiresAt) {
		return models.ErrCIBAExpiredToken
	}

	// If the request already had a resolved UserID, verify it matches.
	if row.UserID != nil && *row.UserID != userID {
		return models.ErrCIBAUserMismatch
	}

	// Mint a plain access token string (opaque; the actual JWT minting
	// follows the same pattern as the authorization_code grant but uses
	// the stored scope and the approving user's ID).
	//
	// We reuse MintCIBATokens which lives in token_ciba.go to keep this
	// function readable.
	accessToken, refreshToken, err := s.MintCIBATokens(ctx, row, userID)
	if err != nil {
		return err
	}

	// Persist approval.
	uid := userID
	row.UserID = &uid
	row.Status = models.BackchannelStatusApproved
	row.AccessToken = accessToken
	row.RefreshToken = refreshToken
	return cibaStore.UpdateBackchannelRequest(ctx, row)
}

// DenyBackchannelRequest is the service-layer operation called when the
// operator's AD callback records user denial.
func (s *Service) DenyBackchannelRequest(ctx context.Context, authReqID string, userID models.ULID) error {
	if s == nil || s.Cfg.CIBA == nil {
		return models.ErrCIBADisabled
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return models.ErrCIBADisabled
	}

	row, err := cibaStore.BackchannelRequestByID(ctx, authReqID)
	if err != nil {
		return models.ErrOAuthInvalidGrant
	}
	if row.Status != models.BackchannelStatusPending {
		return models.ErrOAuthInvalidGrant
	}
	if row.UserID != nil && *row.UserID != userID {
		return models.ErrCIBAUserMismatch
	}

	uid := userID
	row.UserID = &uid
	row.Status = models.BackchannelStatusDenied
	return cibaStore.UpdateBackchannelRequest(ctx, row)
}

// generateAuthReqID produces a cryptographically random 256-bit string
// encoded as base64url (no padding).
func generateAuthReqID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// cibaNotifyError wraps an AuthenticationDevice.Notify failure so handlers
// can map it to 503 without an import cycle.
type cibaNotifyError struct {
	inner error
}

func (e *cibaNotifyError) Error() string {
	if e.inner != nil {
		return "theauth: ciba notify failed: " + e.inner.Error()
	}
	return "theauth: ciba notify failed"
}

func (e *cibaNotifyError) Unwrap() error { return e.inner }

// IsCIBANotifyError reports whether err is a CIBANotifyError.
func IsCIBANotifyError(err error) bool {
	_, ok := err.(*cibaNotifyError)
	return ok
}

// IsCIBAEnabled reports whether CIBA is active on this Service instance: the
// config must have a non-nil CIBAConfig AND the Storage must implement
// CIBAStorage.
func (s *Service) IsCIBAEnabled() bool {
	if s == nil || s.Cfg.CIBA == nil {
		return false
	}
	_, ok := s.Storage.(CIBAStorage)
	return ok
}

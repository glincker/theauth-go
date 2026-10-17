package as

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// ciba.go holds the CIBA (RFC 9509) backchannel authentication service logic. The user approve and
// deny paths are exposed at the root.

// BackchannelAuthRequest is the parsed form body of POST /oauth/bc-authorize.
type BackchannelAuthRequest struct {
	ClientID     string
	ClientSecret string

	// Exactly one of LoginHint, LoginHintToken or IDTokenHint must be present.
	LoginHint      string
	LoginHintToken string
	IDTokenHint    string

	Scope []string

	BindingMessage string

	// ClientNotificationToken is the bearer token for ping-mode callbacks. Empty in poll mode.
	ClientNotificationToken string

	// RequestedExpiry, when positive, overrides the default expiry, capped at CIBAConfig.MaxRequestedExpiry.
	RequestedExpiry int
}

// BackchannelAuthResponse is returned by POST /oauth/bc-authorize on success.
type BackchannelAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// CIBATokenRequest is the CIBA arm of TokenRequest, polling with an auth_req_id.
type CIBATokenRequest struct {
	ClientID     string
	ClientSecret string
	AuthReqID    string
}

// BackchannelAuthenticate handles POST /oauth/bc-authorize: it authenticates the client, requires
// exactly one hint, mints a 256-bit auth_req_id, persists the request and notifies the user's
// authentication device. It returns ErrCIBADisabled when CIBA is not configured or the storage
// lacks CIBAStorage.
func (s *Service) BackchannelAuthenticate(ctx context.Context, req BackchannelAuthRequest) (BackchannelAuthResponse, error) {
	if s == nil || s.Cfg.CIBA == nil {
		return BackchannelAuthResponse{}, models.ErrCIBADisabled
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return BackchannelAuthResponse{}, models.ErrCIBADisabled
	}

	_, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return BackchannelAuthResponse{}, err
	}

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

	if len(req.Scope) == 0 {
		return BackchannelAuthResponse{}, models.ErrCIBAInvalidRequest
	}

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

	// The login hint is forwarded so the operator can resolve it to a user.
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
		// A Notify failure does not undo the stored row. It returns a service-unavailable signal so the
		// client knows the push failed.
		return BackchannelAuthResponse{}, &cibaNotifyError{inner: err}
	}

	return BackchannelAuthResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(expiry.Seconds()),
		Interval:  int(cfg.DefaultInterval.Seconds()),
	}, nil
}

// PollBackchannelToken handles the CIBA grant on POST /oauth/token. It authenticates the client,
// checks expiry, status and poll rate, and returns tokens once approved, or the pending error
// otherwise.
func (s *Service) PollBackchannelToken(ctx context.Context, req CIBATokenRequest) (TokenResponse, error) {
	if s == nil || s.Cfg.CIBA == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	cibaStore, ok := s.Storage.(CIBAStorage)
	if !ok {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}

	client, err := s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}

	if req.AuthReqID == "" {
		return TokenResponse{}, models.ErrCIBAInvalidRequest
	}

	now := time.Now()

	cfg := s.Cfg.CIBA
	row, err := cibaStore.BackchannelRequestByID(ctx, req.AuthReqID)
	if err != nil {
		// An unknown or already cleaned-up auth_req_id is invalid_grant.
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}

	if row.ClientID != client.ClientID {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}

	if !now.Before(row.ExpiresAt) {
		return TokenResponse{}, models.ErrCIBAExpiredToken
	}

	// slow_down fires only when the client polls faster than the absolute MinPollInterval floor.
	if row.LastPollAt != nil {
		elapsed := now.Sub(*row.LastPollAt)
		if elapsed < cfg.MinPollInterval {
			// The interval doubles on each slow_down, capped at MaxRequestedExpiry.
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

	row, err = cibaStore.TouchBackchannelPoll(ctx, req.AuthReqID, now, row.PollInterval)
	if err != nil {
		return TokenResponse{}, err
	}

	switch row.Status {
	case models.BackchannelStatusPending:
		return TokenResponse{}, models.ErrCIBAAuthorizationPending
	case models.BackchannelStatusDenied:
		return TokenResponse{}, models.ErrCIBAAccessDenied
	case cibaStatusConsumed:
		// Tokens are delivered once; an auth_req_id is single use.
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	case models.BackchannelStatusApproved:
		if row.AccessToken == "" {
			return TokenResponse{}, models.ErrCIBAAuthorizationPending
		}
		// Only the winner of the approved to consumed transition gets tokens. Every other poll,
		// concurrent or later, gets invalid_grant.
		won, ok, err := redeemBackchannel(ctx, cibaStore, req.AuthReqID, now)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("redeem backchannel request: %w", err)
		}
		if !ok {
			return TokenResponse{}, models.ErrOAuthInvalidGrant
		}
		return TokenResponse{
			AccessToken:  won.AccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(s.Cfg.AccessTokenTTL.Seconds()),
			RefreshToken: won.RefreshToken,
			Scope:        scopeJoin(won.Scope),
		}, nil
	default:
		return TokenResponse{}, models.ErrCIBAAuthorizationPending
	}
}

// ApproveBackchannelRequest runs when the operator's device callback confirms approval. It verifies
// the user matches any resolved hint, mints the tokens and persists status approved.
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

	if row.UserID != nil && *row.UserID != userID {
		return models.ErrCIBAUserMismatch
	}

	// Tokens come from MintCIBATokens (token_ciba.go), which follows the authorization_code pattern.
	accessToken, refreshToken, err := s.MintCIBATokens(ctx, row, userID)
	if err != nil {
		return err
	}

	uid := userID
	row.UserID = &uid
	row.Status = models.BackchannelStatusApproved
	row.AccessToken = accessToken
	row.RefreshToken = refreshToken
	return cibaStore.UpdateBackchannelRequest(ctx, row)
}

// DenyBackchannelRequest runs when the operator's device callback records a denial.
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

// generateAuthReqID returns 256 random bits, base64url encoded without padding.
func generateAuthReqID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// cibaNotifyError wraps an AuthenticationDevice.Notify failure so handlers can map it to 503.
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

// IsCIBANotifyError reports whether err is a cibaNotifyError.
func IsCIBANotifyError(err error) bool {
	_, ok := err.(*cibaNotifyError)
	return ok
}

// IsCIBAEnabled reports whether CIBA is active on this Service instance: the config must have a
// non-nil CIBAConfig AND the Storage must implement CIBAStorage.
func (s *Service) IsCIBAEnabled() bool {
	if s == nil || s.Cfg.CIBA == nil {
		return false
	}
	_, ok := s.Storage.(CIBAStorage)
	return ok
}

// cibaStatusConsumed is the status of an approved request whose tokens were
// already delivered (see theauth.BackchannelStatusConsumed).
const cibaStatusConsumed = "consumed"

// backchannelRedeemer is the optional storage capability that redeems an
// approved request atomically (theauth.BackchannelRedeemer).
type backchannelRedeemer interface {
	RedeemBackchannelRequest(ctx context.Context, authReqID string, now time.Time) (models.BackchannelRequest, bool, error)
}

// redeemLocks serializes the fallback redeem per auth_req_id within this
// process. It is striped so memory use stays bounded.
var redeemLocks [64]sync.Mutex

func redeemLockFor(authReqID string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(authReqID))
	return &redeemLocks[h.Sum32()%uint32(len(redeemLocks))]
}

// redeemBackchannel moves an approved, unexpired request to consumed and
// returns it with its tokens; ok is true for exactly one caller.
//
// When the storage implements BackchannelRedeemer the claim is one atomic
// storage operation and holds across nodes. Otherwise it falls back to an
// in-process lock keyed by auth_req_id around a read, a status flip through
// UpdateBackchannelRequest and a write. That is correct for a single process
// only: multi node deployments must use a storage that implements
// BackchannelRedeemer (memory, Postgres and SQLite do).
func redeemBackchannel(ctx context.Context, store CIBAStorage, authReqID string, now time.Time) (models.BackchannelRequest, bool, error) {
	if r, ok := store.(backchannelRedeemer); ok {
		return r.RedeemBackchannelRequest(ctx, authReqID, now)
	}
	mu := redeemLockFor(authReqID)
	mu.Lock()
	defer mu.Unlock()
	row, err := store.BackchannelRequestByID(ctx, authReqID)
	if err != nil {
		return models.BackchannelRequest{}, false, nil
	}
	if row.Status != models.BackchannelStatusApproved || !now.Before(row.ExpiresAt) {
		return models.BackchannelRequest{}, false, nil
	}
	claimed := row
	claimed.Status = cibaStatusConsumed
	if err := store.UpdateBackchannelRequest(ctx, claimed); err != nil {
		return models.BackchannelRequest{}, false, fmt.Errorf("mark backchannel request consumed: %w", err)
	}
	return claimed, true, nil
}

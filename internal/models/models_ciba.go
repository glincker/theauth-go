package models

import "time"

// CIBA (RFC 9509) model additions. BackchannelRequest is the persistent
// record for one Client-Initiated Backchannel Authentication flow. Status
// transitions: pending -> approved | denied. Expired rows are cleaned up
// by the operator's own housekeeping; the library never deletes rows
// automatically so audit trails stay intact.

// BackchannelStatus values persisted in backchannel_requests.status.
const (
	BackchannelStatusPending  = "pending"
	BackchannelStatusApproved = "approved"
	BackchannelStatusDenied   = "denied"
)

// CIBA grant type URN per RFC 9509 section 4.
const GrantTypeCIBA = "urn:openid:params:grant-type:ciba"

// CIBA token delivery mode constants.
const (
	CIBADeliveryModePoll = "poll"
	CIBADeliveryModePing = "ping"
)

// BackchannelRequest is the persistent record for one CIBA flow.
type BackchannelRequest struct {
	// AuthReqID is the opaque handle returned to the client on
	// POST /oauth/bc-authorize. 256-bit, base64url-encoded.
	AuthReqID string

	// ClientID is the registered OAuth client that initiated the request.
	ClientID string

	// UserID is the resolved subject (operator sets this via
	// ApproveBackchannelAuth; nil until approved or when derived from
	// login_hint resolution at request time). Stored so the approve path
	// can verify that the correct user acts.
	UserID *ULID

	// LoginHint, LoginHintToken, IDTokenHint carry the raw hint values
	// submitted by the client. Operators use these in their AD notification
	// to locate the correct user.
	LoginHint      string
	LoginHintToken string
	IDTokenHint    string

	// Scope is the requested scope list.
	Scope []string

	// BindingMessage is the optional short human-readable string shown on
	// the Authentication Device.
	BindingMessage string

	// ClientNotificationToken is the bearer token the AS uses when calling
	// the client's notification endpoint (Ping mode only). Stored opaque
	// (the AS never inspects it); empty for Poll mode requests.
	ClientNotificationToken string

	// Status is the current lifecycle state: pending / approved / denied.
	Status string

	// AccessToken, RefreshToken, IDToken are provisioned by
	// ApproveBackchannelAuth and returned on the next successful poll.
	// Stored encrypted at rest (opaque bytes).
	AccessToken  string
	RefreshToken string
	IDToken      string

	// PollInterval is the minimum seconds between token polls. The AS
	// doubles this on slow_down responses.
	PollInterval int

	// LastPollAt tracks the timestamp of the most recent token poll so
	// the slow_down check can be enforced.
	LastPollAt *time.Time

	// ExpiresAt is the hard deadline for the auth_req_id. Polling after
	// this returns expired_token.
	ExpiresAt time.Time

	CreatedAt time.Time
}

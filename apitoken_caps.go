package theauth

import (
	"context"
	"errors"
	"time"
)

// AbilityRoot is the reserved ability that implies every other ability.
const AbilityRoot = "root"

// Owner kinds an APIToken can belong to.
const (
	OwnerKindUser           = "user"
	OwnerKindServiceAccount = "service_account"
)

// Device authorization request states.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
	DeviceStatusRedeemed = "redeemed"
)

// APIToken is a stored scoped bearer token. Only the SHA-256 of the secret is kept.
type APIToken struct {
	ID         ULID       `json:"id"`
	OwnerID    ULID       `json:"ownerId"`
	OwnerKind  string     `json:"ownerKind"`
	Name       string     `json:"name"`
	Abilities  []string   `json:"abilities"`
	TokenHash  []byte     `json:"-"`
	Hint       string     `json:"hint"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Usable reports whether the token is neither revoked nor expired at now.
func (t APIToken) Usable(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}

// DeviceCode is one RFC 8628 device authorization request.
type DeviceCode struct {
	ID                 ULID       `json:"id"`
	DeviceCodeHash     []byte     `json:"-"`
	UserCode           string     `json:"userCode"`
	Status             string     `json:"status"`
	ClientName         string     `json:"clientName"`
	RequestedAbilities []string   `json:"requestedAbilities"`
	ApprovedAbilities  []string   `json:"approvedAbilities,omitempty"`
	ApproverID         *ULID      `json:"approverId,omitempty"`
	RequesterIP        string     `json:"requesterIp"`
	RequesterUA        string     `json:"requesterUserAgent"`
	IntervalSeconds    int        `json:"intervalSeconds"`
	LastPolledAt       *time.Time `json:"lastPolledAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	ExpiresAt          time.Time  `json:"expiresAt"`
}

// DeviceDecision is the approver's verdict applied by DecideDeviceCode.
type DeviceDecision struct {
	Approve    bool
	ApproverID ULID
	Abilities  []string
}

// ErrDeviceUserCodeTaken is returned by InsertDeviceCode when the user code collides with a live request.
var ErrDeviceUserCodeTaken = errors.New("theauth: device user code already in use")

// APITokenStorage is the capability behind scoped API tokens. Set
// Config.APITokens only with a storage that implements it.
type APITokenStorage interface {
	InsertAPIToken(ctx context.Context, t APIToken) (APIToken, error)
	// APITokenByHash returns ErrStorageNotFound when no token matches.
	APITokenByHash(ctx context.Context, hash []byte) (*APIToken, error)
	APITokenByID(ctx context.Context, id ULID) (*APIToken, error)
	// APITokensByOwner returns every token for the owner, newest first.
	APITokensByOwner(ctx context.Context, ownerID ULID) ([]APIToken, error)
	// ListAPITokens returns every token, newest first.
	ListAPITokens(ctx context.Context) ([]APIToken, error)
	// RevokeAPIToken is idempotent for an already revoked token and returns
	// ErrStorageNotFound when the ID is unknown.
	RevokeAPIToken(ctx context.Context, id ULID, at time.Time) error
	// RevokeAPITokensByOwner revokes every live token of the owner and
	// returns how many it changed.
	RevokeAPITokensByOwner(ctx context.Context, ownerID ULID, at time.Time) (int, error)
	TouchAPITokenLastUsed(ctx context.Context, id ULID, at time.Time) error
}

// DeviceCodeStorage is the capability behind the RFC 8628 device grant.
type DeviceCodeStorage interface {
	// InsertDeviceCode returns ErrDeviceUserCodeTaken on a user code collision.
	InsertDeviceCode(ctx context.Context, d DeviceCode) error
	DeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	DeviceCodeByHash(ctx context.Context, hash []byte) (*DeviceCode, error)
	// DecideDeviceCode moves a pending, unexpired request to approved or
	// denied in one compare-and-set step; otherwise ErrStorageNotFound.
	DecideDeviceCode(ctx context.Context, userCode string, d DeviceDecision, now time.Time) error
	// ClaimDeviceCode atomically moves an approved, unexpired request to
	// redeemed and returns it. Exactly one concurrent caller succeeds; the
	// rest get ErrStorageNotFound.
	ClaimDeviceCode(ctx context.Context, hash []byte, now time.Time) (*DeviceCode, error)
	RecordDevicePoll(ctx context.Context, hash []byte, at time.Time, intervalSeconds int) error
	// DeleteExpiredDeviceCodes removes requests that expired before the cutoff.
	DeleteExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error)
}

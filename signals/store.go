package signals

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by a Store when a stream does not exist.
var ErrNotFound = errors.New("signals: not found")

// Delivery methods (SSF section 8.1.1).
const (
	MethodPush = "https://schemas.openid.net/secevent/risc/delivery-method/push"
	MethodPoll = "https://schemas.openid.net/secevent/risc/delivery-method/poll"
	// MethodPushRFC8935 is the RFC 8935 identifier, accepted as an alias.
	MethodPushRFC8935 = "urn:ietf:rfc:8935"
	// MethodPollRFC8936 is the RFC 8936 identifier, accepted as an alias.
	MethodPollRFC8936 = "urn:ietf:rfc:8936"
)

// Stream status values (SSF section 8.1.4).
const (
	StatusEnabled  = "enabled"
	StatusPaused   = "paused"
	StatusDisabled = "disabled"
)

// DeliveryConfig is the delivery member of a stream.
type DeliveryConfig struct {
	Method string `json:"method"`
	// EndpointURL is the receiver push endpoint (push) or the transmitter
	// poll endpoint (poll, set by the transmitter).
	EndpointURL string `json:"endpoint_url,omitempty"`
	// AuthorizationHeader is sent verbatim on push. It is never returned by
	// the management API.
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// Stream is one transmitter to receiver event stream.
type Stream struct {
	ID         string         `json:"stream_id"`
	ReceiverID string         `json:"receiver_id"`
	Audience   []string       `json:"aud,omitempty"`
	Delivery   DeliveryConfig `json:"delivery"`
	// EventsRequested is what the receiver asked for; EventsDelivered is the
	// intersection with what the transmitter supports.
	EventsRequested []string  `json:"events_requested,omitempty"`
	EventsDelivered []string  `json:"events_delivered,omitempty"`
	Description     string    `json:"description,omitempty"`
	Status          string    `json:"status"`
	StatusReason    string    `json:"status_reason,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// IsPush reports whether the stream delivers by push.
func (s Stream) IsPush() bool { return normalizeMethod(s.Delivery.Method) == MethodPush }

func normalizeMethod(m string) string {
	switch m {
	case MethodPush, MethodPushRFC8935:
		return MethodPush
	case MethodPoll, MethodPollRFC8936:
		return MethodPoll
	}
	return ""
}

// PendingSET is a signed SET waiting for delivery or acknowledgement.
type PendingSET struct {
	ID        string
	StreamID  string
	JTI       string
	Token     string
	Push      bool
	Attempts  int
	NextAt    time.Time
	CreatedAt time.Time
}

// Store persists streams, their subjects and the delivery queue.
//
// Implementations: NewMemoryStore here, and the sqlite and postgres storage
// packages (SignalsStore). Methods must be safe for concurrent use.
type Store interface {
	CreateStream(ctx context.Context, s Stream) error
	// GetStream returns ErrNotFound for an unknown id.
	GetStream(ctx context.Context, id string) (Stream, error)
	// ListStreams returns the streams of receiverID, or all streams when
	// receiverID is empty.
	ListStreams(ctx context.Context, receiverID string) ([]Stream, error)
	// UpdateStream replaces the stored stream and re-tags queued SETs with
	// the new delivery method. ErrNotFound for an unknown id.
	UpdateStream(ctx context.Context, s Stream) error
	// DeleteStream removes the stream, its subjects and queued SETs.
	DeleteStream(ctx context.Context, id string) error

	AddSubject(ctx context.Context, streamID, key string, subject []byte) error
	RemoveSubject(ctx context.Context, streamID, key string) error
	HasSubject(ctx context.Context, streamID, key string) (bool, error)
	CountSubjects(ctx context.Context, streamID string) (int, error)

	Enqueue(ctx context.Context, p PendingSET) error
	// DuePush returns up to limit queued push SETs with NextAt <= now.
	DuePush(ctx context.Context, now time.Time, limit int) ([]PendingSET, error)
	// Pending returns up to limit unacknowledged SETs of a stream, oldest
	// first.
	Pending(ctx context.Context, streamID string, limit int) ([]PendingSET, error)
	// CountPending counts unacknowledged SETs of a stream.
	CountPending(ctx context.Context, streamID string) (int, error)
	MarkAttempt(ctx context.Context, id string, attempts int, next time.Time) error
	// Ack removes the SETs with the given jtis from the stream and returns
	// how many were removed.
	Ack(ctx context.Context, streamID string, jtis []string) (int, error)
	Drop(ctx context.Context, id string) error
}

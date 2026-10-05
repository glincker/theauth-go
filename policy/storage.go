package policy

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a policy does not exist.
var ErrNotFound = errors.New("policy: not found")

// SubjectKind says what a policy is attached to.
type SubjectKind string

// Subject kinds. Policies attached to a token act as a permission boundary:
// they can only narrow what the token owner may do.
const (
	SubjectUser  SubjectKind = "user"
	SubjectGroup SubjectKind = "group"
	SubjectRole  SubjectKind = "role"
	SubjectToken SubjectKind = "token"
)

// Subject identifies the user, group, role or API token a policy is attached to.
type Subject struct {
	Kind SubjectKind `json:"kind"`
	ID   string      `json:"id"`
}

// Record is a stored policy document. Document is the validated JSON form.
type Record struct {
	ID        string
	Name      string
	Document  []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Attached is a stored policy together with the subject it is attached to.
type Attached struct {
	Subject Subject
	Record  Record
}

// Storage is the optional capability a backend implements to persist
// policies and their attachments. Implementations must be safe for
// concurrent use and must treat Document as opaque bytes.
type Storage interface {
	// PutPolicy upserts by ID, keeping CreatedAt on update.
	PutPolicy(ctx context.Context, r Record) error
	// GetPolicy returns ErrNotFound when the ID is unknown.
	GetPolicy(ctx context.Context, id string) (*Record, error)
	// ListPolicies returns every policy ordered by ID.
	ListPolicies(ctx context.Context) ([]Record, error)
	// DeletePolicy removes the policy and all its attachments, and is a
	// no-op for an unknown ID.
	DeletePolicy(ctx context.Context, id string) error
	// AttachPolicy is idempotent and returns ErrNotFound for an unknown policy.
	AttachPolicy(ctx context.Context, s Subject, policyID string) error
	// DetachPolicy is idempotent.
	DetachPolicy(ctx context.Context, s Subject, policyID string) error
	// PoliciesFor returns every policy attached to any of the subjects,
	// ordered by policy ID then subject kind and ID.
	PoliciesFor(ctx context.Context, subjects []Subject) ([]Attached, error)
}

// PolicyStorage is an alias of Storage matching the other capability names.
type PolicyStorage = Storage

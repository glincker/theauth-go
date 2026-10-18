package audit

import (
	"context"

	iaudit "github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// Input source kinds recorded in the provenance of an audit row.
const (
	InputUserMessage       = iaudit.InputUserMessage
	InputToolOutput        = iaudit.InputToolOutput
	InputRetrievedDocument = iaudit.InputRetrievedDocument
	InputAgent             = iaudit.InputAgent
)

// Hash algorithm tags in the "alg" field of a provenance record.
const (
	InputHashHMAC   = iaudit.InputHashHMAC
	InputHashSHA256 = iaudit.InputHashSHA256
)

// InputSource is one input to a call. Give Content (hashed, never stored) or a Hash made by
// InputHasher.Hash.
type InputSource = iaudit.InputSource

// InputHasher hashes input content. The zero value is unkeyed SHA-256, NewInputHasher(key) the keyed form.
type InputHasher = iaudit.InputHasher

// InputKinds lists the accepted input kinds.
func InputKinds() []string { return iaudit.InputKinds() }

// NewInputHasher returns a keyed hasher (HMAC-SHA256 under a derived subkey), or the unkeyed one
// for an empty key. Keys under 16 bytes are refused.
func NewInputHasher(key []byte) (InputHasher, error) { return iaudit.NewInputHasher(key) }

// WithInputs declares the inputs of the call running under ctx. Authorization decisions and tool
// guard calls made with this context record only the hashes of the inputs.
func WithInputs(ctx context.Context, inputs ...InputSource) context.Context {
	return iaudit.WithInputs(ctx, inputs...)
}

// BuildInputProvenance returns the stored provenance record for inputs, or nil when none is valid.
func BuildInputProvenance(h InputHasher, inputs []InputSource) map[string]any {
	return iaudit.BuildInputProvenance(h, inputs)
}

// ProvenanceNeedle returns the substring a stored input_provenance text contains when it matches
// f. Backends match it literally (instr, strpos, LOCATE), never with LIKE.
func ProvenanceNeedle(f models.ProvenanceFilter) (string, error) { return iaudit.ProvenanceNeedle(f) }

// ErrBadProvenanceFilter is returned for an unknown kind or a malformed hash in a filter.
var ErrBadProvenanceFilter = models.ErrBadProvenanceFilter

// ErrAuditProvenanceUnsupported is returned when the backend cannot serve a provenance filter.
var ErrAuditProvenanceUnsupported = models.ErrAuditProvenanceUnsupported

// Rotating pseudonyms. See the audit trail docs for the scheme.

// Rotation is the pseudonym rotation policy.
type Rotation = iaudit.Rotation

// RotationState holds a store's rotation policy and sweep bookkeeping.
type RotationState = iaudit.RotationState

// PeriodSecretStore is the per period secret storage a backend provides.
type PeriodSecretStore = iaudit.PeriodSecretStore

// Pseudonymizer makes the pseudonyms of a row at write time.
type Pseudonymizer = iaudit.Pseudonymizer

// PseudonymKeys is the set of secrets a verifier holds.
type PseudonymKeys = iaudit.PseudonymKeys

// PeriodOf returns the rotation period number of t.
var PeriodOf = iaudit.PeriodOf

// RotatingPseudonym returns the tagged pseudonym of id under the secret of period.
var RotatingPseudonym = iaudit.RotatingPseudonym

// NewPeriodSecret returns a fresh random 32 byte period secret.
var NewPeriodSecret = iaudit.NewPeriodSecret

// ShredStalePeriods deletes the secrets of periods older than current-retain.
var ShredStalePeriods = iaudit.ShredStalePeriods

// StableKeys wraps a lone installation secret as PseudonymKeys.
var StableKeys = iaudit.StableKeys

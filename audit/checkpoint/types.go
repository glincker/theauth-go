package checkpoint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Signer signs checkpoint bytes. Wrap a KMS or HSM call here; the private key
// never has to be in process.
type Signer interface {
	// KeyID identifies the key. Verifiers pick the public key by this id.
	KeyID() string
	// Sign returns a 64 byte Ed25519 signature over message.
	Sign(message []byte) ([]byte, error)
}

// JWK is an Ed25519 public key as a JSON Web Key (kty OKP, crv Ed25519).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// PublicKey is an Ed25519 public key and the id it is published under.
type PublicKey struct {
	KeyID     string `json:"keyId"`
	PublicKey JWK    `json:"publicKey"`
}

// Checkpoint is a signed tree head: the state of the log at a point in time.
type Checkpoint struct {
	Version int `json:"version"`
	// Alg is always "Ed25519". Anything else is rejected.
	Alg   string `json:"alg"`
	KeyID string `json:"keyId"`
	// Size is the number of leaves in the tree.
	Size int64 `json:"size"`
	// RootHash is the hex SHA-256 Merkle root (RFC 6962).
	RootHash string `json:"rootHash"`
	// Timestamp is the signing time in milliseconds since the epoch.
	Timestamp int64 `json:"timestamp"`
	// Since and Until bound the row timestamps (ms) the tree covers; nil means unbounded.
	Since *int64 `json:"since"`
	Until *int64 `json:"until"`
	// Signature is the base64url Ed25519 signature over the other fields.
	Signature string `json:"signature"`
}

// InclusionProof shows one row is a leaf of a checkpoint's tree.
type InclusionProof struct {
	Version int    `json:"version"`
	RowID   string `json:"rowId"`
	// LeafIndex is the zero based position of the row's leaf.
	LeafIndex int64 `json:"leafIndex"`
	// TreeSize must equal the checkpoint size.
	TreeSize int64    `json:"treeSize"`
	LeafHash string   `json:"leafHash"`
	Path     []string `json:"path"`
}

// ConsistencyProof shows a newer checkpoint extends an older one.
type ConsistencyProof struct {
	Version int      `json:"version"`
	OldSize int64    `json:"oldSize"`
	NewSize int64    `json:"newSize"`
	Path    []string `json:"path"`
}

// RevealedField is a field a receipt reveals, with the salt of its commitment.
type RevealedField struct {
	Value any    `json:"value"`
	Salt  string `json:"salt"`
}

// Decision is the row part of a receipt.
type Decision struct {
	RowID string `json:"rowId"`
	// RowHash is the row's chain hash. It covers every field, hidden ones too.
	RowHash     string                   `json:"rowHash"`
	HashVersion int                      `json:"hashVersion"`
	Revealed    map[string]RevealedField `json:"revealed"`
	// Commitments are the hex commitments of the fields that are not revealed.
	Commitments map[string]string `json:"commitments"`
}

// Receipt is a decision, its inclusion proof and the signed checkpoint.
type Receipt struct {
	Version    int            `json:"version"`
	Decision   Decision       `json:"decision"`
	Proof      InclusionProof `json:"proof"`
	Checkpoint Checkpoint     `json:"checkpoint"`
}

// Reason says why a verification failed. The codes are stable.
type Reason string

// Failure reasons, identical to the TypeScript SDK.
const (
	ReasonMalformed      Reason = "malformed"
	ReasonUnsupportedAlg Reason = "unsupported_alg"
	ReasonUnknownKey     Reason = "unknown_key"
	ReasonBadSignature   Reason = "bad_signature"
	ReasonSizeMismatch   Reason = "size_mismatch"
	ReasonScopeMismatch  Reason = "scope_mismatch"
	ReasonBadProof       Reason = "bad_proof"
	ReasonLeafMismatch   Reason = "leaf_mismatch"
	ReasonBadCommitment  Reason = "bad_commitment"
	checkpointVersion           = 1
	signatureBytes              = 64
	publicKeyBytes              = 32
	algEd25519                  = "Ed25519"
	signDomain                  = "theauth.audit.checkpoint.v1\n"
	saltDomain                  = "theauth.audit.receipt.salt.v1"
	commitDomain                = "theauth.audit.receipt.field.v1"
	leafVersion                 = 1
	jwkKty                      = "OKP"
	jwkCrv                      = "Ed25519"
	maxSafeInteger       int64  = 1<<53 - 1
)

// Outcome is the result of a verification.
type Outcome struct {
	Valid  bool
	Reason Reason
}

// OK reports a successful verification.
func OK() Outcome { return Outcome{Valid: true} }

func fail(r Reason) Outcome { return Outcome{Reason: r} }

// Error is returned by the Create functions. Code is stable.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is matches another *Error with the same code, so errors.Is(err, ErrLogMismatch) works.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Code == e.Code
}

// Sentinels for errors.Is.
var (
	ErrInvalidCheckpoint = &Error{Code: "INVALID_CHECKPOINT"}
	ErrLogMismatch       = &Error{Code: "LOG_MISMATCH"}
	ErrRowNotFound       = &Error{Code: "ROW_NOT_FOUND"}
	ErrInvalidField      = &Error{Code: "INVALID_FIELD"}
	ErrInvalidOrder      = &Error{Code: "INVALID_ORDER"}
	ErrScopeMismatch     = &Error{Code: "SCOPE_MISMATCH"}
)

func newErr(base *Error, format string, args ...any) error {
	return &Error{Code: base.Code, Message: fmt.Sprintf(format, args...)}
}

var hashHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHashHex(s string) bool { return hashHex.MatchString(s) }

func hexList(in [][]byte) []string {
	out := make([]string, len(in))
	for i, b := range in {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func decodeHexList(in []string) ([][]byte, bool) {
	out := make([][]byte, len(in))
	for i, s := range in {
		if !isHashHex(s) {
			return nil, false
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, false
		}
		out[i] = b
	}
	return out, true
}

// requireKeys checks that every key is present and not null in a JSON object.
func requireKeys(data []byte, keys ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || (bytes.Equal(bytes.TrimSpace(v), []byte("null")) && k != "since" && k != "until") {
			return fmt.Errorf("checkpoint: missing field %q", k)
		}
	}
	return nil
}

// UnmarshalJSON rejects a checkpoint with a missing or null field.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "version", "alg", "keyId", "size", "rootHash", "timestamp", "since", "until", "signature"); err != nil {
		return err
	}
	type plain Checkpoint
	return json.Unmarshal(data, (*plain)(c))
}

// UnmarshalJSON rejects a proof with a missing or null field.
func (p *InclusionProof) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "version", "rowId", "leafIndex", "treeSize", "leafHash", "path"); err != nil {
		return err
	}
	type plain InclusionProof
	return json.Unmarshal(data, (*plain)(p))
}

// UnmarshalJSON rejects a proof with a missing or null field.
func (p *ConsistencyProof) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "version", "oldSize", "newSize", "path"); err != nil {
		return err
	}
	type plain ConsistencyProof
	return json.Unmarshal(data, (*plain)(p))
}

// UnmarshalJSON rejects a decision with a missing or null field.
func (d *Decision) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "rowId", "rowHash", "hashVersion", "revealed", "commitments"); err != nil {
		return err
	}
	type plain Decision
	return json.Unmarshal(data, (*plain)(d))
}

// UnmarshalJSON rejects a receipt with a missing or null part.
func (r *Receipt) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "version", "decision", "proof", "checkpoint"); err != nil {
		return err
	}
	type plain Receipt
	return json.Unmarshal(data, (*plain)(r))
}

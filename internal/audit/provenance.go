package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Input source kinds. They match the TypeScript SDK (audit/provenance.ts).
const (
	InputUserMessage       = "user_message"
	InputToolOutput        = "tool_output"
	InputRetrievedDocument = "retrieved_document"
	InputAgent             = "agent"
)

// InputKinds lists the accepted input source kinds.
func InputKinds() []string {
	return []string{InputUserMessage, InputToolOutput, InputRetrievedDocument, InputAgent}
}

// ValidInputKind reports whether k is one of the accepted kinds.
func ValidInputKind(k string) bool {
	switch k {
	case InputUserMessage, InputToolOutput, InputRetrievedDocument, InputAgent:
		return true
	}
	return false
}

// Hash algorithm tags written to the provenance record, so a reader knows how Content was hashed.
const (
	InputHashHMAC   = "hmac-sha256"
	InputHashSHA256 = "sha256"
)

const (
	maxInputSources = 32
	maxInputIDLen   = 256
	// minInputKeyLen is the shortest accepted InputHasher key.
	minInputKeyLen = 16

	inputDomain    = "theauth.audit.input.v1:"
	inputSubkeyTag = "theauth.audit.input-subkey.v1"
)

var inputHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrInputKeyTooShort is returned for a non-empty hash key under 16 bytes.
var ErrInputKeyTooShort = errors.New("theauth: audit input hash key must be at least 16 bytes")

// InputSource is one input to a call: where it came from, and a hash of what it was. Give Content
// (hashed here, then dropped) or a Hash computed with InputHasher.Hash.
type InputSource struct {
	Kind string
	// ID identifies the source, for example a message id or tool call id. Stored as given.
	ID string
	// Content is hashed and never stored.
	Content string
	// Hash is a lowercase hex digest from InputHasher.Hash, for callers that already have it.
	Hash string
}

// InputHasher hashes input content for the audit record. With a key it is HMAC-SHA256 under a
// subkey derived from the key, so a short or guessable input (a one word user message) cannot be
// confirmed by someone who only holds the audit rows. The subkey is
// HMAC-SHA256(key, "theauth.audit.input-subkey.v1"), so the same master key can also feed other
// audit uses without sharing key material. The zero value is unkeyed: SHA-256 with a domain
// prefix, the same digest the TypeScript SDK computes.
type InputHasher struct{ sub []byte }

// NewInputHasher returns a keyed hasher, or the unkeyed one when key is empty.
func NewInputHasher(key []byte) (InputHasher, error) {
	if len(key) == 0 {
		return InputHasher{}, nil
	}
	if len(key) < minInputKeyLen {
		return InputHasher{}, ErrInputKeyTooShort
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(inputSubkeyTag))
	return InputHasher{sub: m.Sum(nil)}, nil
}

// Alg is the algorithm tag recorded next to hashes this hasher makes.
func (h InputHasher) Alg() string {
	if len(h.sub) == 0 {
		return InputHashSHA256
	}
	return InputHashHMAC
}

// Hash returns the lowercase hex digest of content.
func (h InputHasher) Hash(content string) string {
	if len(h.sub) == 0 {
		sum := sha256.Sum256([]byte(inputDomain + content))
		return hex.EncodeToString(sum[:])
	}
	m := hmac.New(sha256.New, h.sub)
	m.Write([]byte(inputDomain + content))
	return hex.EncodeToString(m.Sum(nil))
}

// BuildInputProvenance turns caller supplied inputs into the stored record:
//
//	{"v":1,"alg":"hmac-sha256","sources":[{"kind","id"?,"hash"}],"keys":["<kind>:<hash>"]}
//
// keys repeats each source so a query can filter with a plain substring match on every database.
// Entries with an unknown kind, or with neither content nor a valid hash, are dropped, as are
// duplicates and anything past 32 sources. It returns nil when nothing is left.
func BuildInputProvenance(h InputHasher, inputs []InputSource) map[string]any {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) > maxInputSources {
		inputs = inputs[:maxInputSources]
	}
	sources := make([]any, 0, len(inputs))
	keys := make([]any, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, in := range inputs {
		if !ValidInputKind(in.Kind) {
			continue
		}
		var hash string
		switch {
		case in.Content != "":
			hash = h.Hash(in.Content)
		case inputHashPattern.MatchString(in.Hash):
			hash = in.Hash
		default:
			continue
		}
		key := in.Kind + ":" + hash
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		src := map[string]any{"kind": in.Kind, "hash": hash}
		if id := truncateRunes(in.ID, maxInputIDLen); id != "" {
			src["id"] = id
		}
		sources = append(sources, src)
		keys = append(keys, key)
	}
	if len(sources) == 0 {
		return nil
	}
	return map[string]any{"v": 1, "alg": h.Alg(), "sources": sources, "keys": keys}
}

// MergeInputProvenance returns base with the captured record's fields added. base is not modified.
func MergeInputProvenance(base, captured map[string]any) map[string]any {
	if len(captured) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(captured))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range captured {
		out[k] = v
	}
	return out
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

type ctxKeyInputsT struct{}

var ctxKeyInputs ctxKeyInputsT

// WithInputs declares the inputs of the call running under ctx. The audit writer reads them from
// the context when it emits the decision row, so they are trusted: tool arguments cannot add or
// forge a source. Inputs add to any already declared on ctx. Content stays in memory only until the
// event is emitted, then only its hash is kept.
func WithInputs(ctx context.Context, inputs ...InputSource) context.Context {
	if len(inputs) == 0 {
		return ctx
	}
	prev := InputsFromContext(ctx)
	all := make([]InputSource, 0, len(prev)+len(inputs))
	all = append(append(all, prev...), inputs...)
	return context.WithValue(ctx, ctxKeyInputs, all)
}

// InputsFromContext returns the inputs declared with WithInputs.
func InputsFromContext(ctx context.Context) []InputSource {
	in, _ := ctx.Value(ctxKeyInputs).([]InputSource)
	return in
}

// ProvenanceNeedle returns the substring a stored input_provenance text contains when the row
// matches f. Kind names and hex digests carry no quote or backslash, so the needle needs no
// escaping, and stores must match it with a literal search (instr, strpos, LOCATE), not LIKE, where
// the underscore in "user_message" is a wildcard. An empty filter returns "".
func ProvenanceNeedle(f models.ProvenanceFilter) (string, error) {
	if f.Kind != "" && !ValidInputKind(f.Kind) {
		return "", fmt.Errorf("%w: unknown kind %q", models.ErrBadProvenanceFilter, f.Kind)
	}
	if f.Hash != "" && !inputHashPattern.MatchString(f.Hash) {
		return "", fmt.Errorf("%w: hash must be 64 lowercase hex characters", models.ErrBadProvenanceFilter)
	}
	switch {
	case f.Kind != "" && f.Hash != "":
		return `"` + f.Kind + ":" + f.Hash + `"`, nil
	case f.Hash != "":
		return ":" + f.Hash + `"`, nil
	case f.Kind != "":
		return `"` + f.Kind + ":", nil
	}
	return "", nil
}

// MatchesProvenance reports whether a stored record (as the marshaled JSON text) matches f. The
// memory store uses it so every backend agrees.
func MatchesProvenance(recordJSON, needle string) bool {
	return needle == "" || strings.Contains(recordJSON, needle)
}

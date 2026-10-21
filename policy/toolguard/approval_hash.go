package toolguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// reservedArgKey reports whether a top level argument key belongs to the SDK. The TypeScript
// library strips the same keys before hashing (audit/reserved.ts): everything starting with
// "theauth" in any case, plus approvalId and inputProvenance. A caller supplied argument with one
// of these names would otherwise read as a guard verdict or a spent approval, so it is not part
// of what an approver signs off on.
func reservedArgKey(k string) bool {
	return k == "approvalId" || k == "inputProvenance" || strings.HasPrefix(strings.ToLower(k), "theauth")
}

// HashApprovalAction returns the hex SHA-256 of the canonical JSON of what an approver signs off
// on: the action, the resource and the arguments. Object keys are sorted at every depth (they are
// Go maps when encoded), numbers keep their decimal text, and reserved top level keys are
// dropped. Nil arguments and an empty object hash the same. args is a struct, a map with string
// keys or nil; it is round tripped through encoding/json, so json tags apply. An argument value
// that cannot be encoded (a channel, a cycle) returns an error, and callers must never treat an
// error as a match.
//
// Number text is canonicalized: an integer keeps its exact digits, any other number (a fraction, an
// exponent, "-0") is parsed as float64 and written the way encoding/json writes a float64. So
// 1, 1.0 and 1e0 hash the same whether the caller decoded with UseNumber or not.
//
// The digest equals the TypeScript hash (packages/core/src/approval/canonical.ts) for JSON shaped
// arguments, checked against shared vectors (tests/fixtures/approval-hash-vectors.json in the
// TypeScript repo). One edge stays: an integer beyond 2^53 is exact here but a JavaScript number has
// already lost its low digits before it is hashed, so such a value cannot match across languages
// unless the TypeScript caller passes a bigint.
func HashApprovalAction(action, resource string, args any) (string, error) {
	if h, ok := fastHashApproval(action, resource, args); ok {
		return h, nil
	}
	return hashApprovalSlow(action, resource, args)
}

// hashApprovalSlow is the reference implementation: it round trips the arguments through
// encoding/json, which handles every value type. The fast path must give the same digest.
func hashApprovalSlow(action, resource string, args any) (string, error) {
	norm, err := normalizeArgs(args)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(map[string]any{"action": action, "resource": resource, "arguments": norm})
	if err != nil {
		return "", fmt.Errorf("toolguard: hash approval: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeArgs(args any) (any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("toolguard: encode approval arguments: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("toolguard: decode approval arguments: %w", err)
	}
	v, err = canonNumbers(v)
	if err != nil {
		return nil, err
	}
	switch m := v.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		for k := range m {
			if reservedArgKey(k) {
				delete(m, k)
			}
		}
		return m, nil
	}
	return v, nil
}

// canonNumbers rewrites every json.Number in a decoded value to its canonical text.
func canonNumbers(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		return canonNumber(x)
	case []any:
		for i := range x {
			c, err := canonNumbers(x[i])
			if err != nil {
				return nil, err
			}
			x[i] = c
		}
	case map[string]any:
		for k := range x {
			c, err := canonNumbers(x[k])
			if err != nil {
				return nil, err
			}
			x[k] = c
		}
	}
	return v, nil
}

func canonNumber(n json.Number) (json.Number, error) {
	s := n.String()
	digits := strings.TrimPrefix(s, "-")
	if s != "-0" && strings.Trim(digits, "0123456789") == "" {
		return n, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("toolguard: approval argument number %q is out of range", s)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("toolguard: encode approval argument number: %w", err)
	}
	return json.Number(raw), nil
}

package toolguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
// The digest is stable across runs and nodes of this library. It is not promised byte for byte
// equal to the TypeScript hash for every input (string escaping and number formatting differ at
// the edges), so compare hashes only between servers of the same library.
func HashApprovalAction(action, resource string, args any) (string, error) {
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

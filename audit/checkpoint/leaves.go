package checkpoint

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// Hash versions. TypeScript rows are 1 (raw ids) and 2 (id pseudonyms); rows of
// the Go audit chain use GoChainHashVersion and the GoChainFields set.
const (
	GoChainHashVersion = 101
)

// FieldsV1 and FieldsV2 are the field sets of TypeScript rows.
var (
	FieldsV2 = []string{"id", "action", "resource", "parameters", "result", "reason", "durationMs", "tokensCost", "ip", "userAgent", "cacheHit", "timestamp", "policyVersion", "delegationChain", "inputProvenance", "idPseudonyms"}
	FieldsV1 = []string{"id", "action", "resource", "parameters", "result", "reason", "durationMs", "tokensCost", "ip", "userAgent", "cacheHit", "timestamp", "agentId", "userId"}
	// GoChainFields are the receipt fields of a Go chain row. The personal ids
	// (actor user, session, subject, actor, approver) are left out: they are
	// erasable, and the row hash still covers them.
	GoChainFields = []string{"id", "organizationId", "action", "targetType", "targetId", "metadata", "ip", "userAgent", "createdAtMicro", "policyVersion", "delegationChain", "inputProvenance", "chainSeq", "prevHash"}
)

// FieldsFor returns the receipt field names for a hash version.
func FieldsFor(hashVersion int) []string {
	switch {
	case hashVersion == GoChainHashVersion:
		return GoChainFields
	case hashVersion >= 2:
		return FieldsV2
	}
	return FieldsV1
}

// Row is one chained audit row as the Merkle tree sees it.
type Row struct {
	ID string
	// Hash is the row's chain hash. Rows with an empty Hash are not in the log.
	Hash        string
	HashVersion int
	// TimestampMs orders the log (with ID) and bounds a checkpoint's range.
	TimestampMs int64
	// Fields holds a value for every name in FieldsFor(HashVersion). A missing name commits to null.
	Fields map[string]any
}

// Source supplies the chained rows of a log. Order does not matter, the
// package sorts by (TimestampMs, ID).
type Source interface {
	Rows(ctx context.Context) ([]Row, error)
}

// Log is a row source plus the key the receipt salts derive from. The salt key
// is the audit key; it lets the operator rebuild every salt without storing it.
type Log struct {
	Source  Source
	SaltKey []byte
}

type leaf struct {
	row         Row
	fieldValues map[string]any
	salts       map[string]string
	commitments map[string]string
	hash        []byte
}

func fieldSalt(key []byte, rowHash, field string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(saltDomain + "\x00" + rowHash + "\x00" + field))
	return hex.EncodeToString(m.Sum(nil))
}

func fieldCommitment(field, salt string, value any) (string, error) {
	c, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(commitDomain + "\x00" + field + "\x00" + salt + "\x00" + c))
	return hex.EncodeToString(sum[:]), nil
}

// leafPreimage is the canonical leaf bytes. The verifier rebuilds exactly this.
func leafPreimage(rowID, rowHash string, hashVersion int, commitments map[string]string) ([]byte, error) {
	fields := make(map[string]any, len(commitments))
	for k, v := range commitments {
		fields[k] = v
	}
	s, err := CanonicalJSON(map[string]any{"v": leafVersion, "rowId": rowID, "rowHash": rowHash, "hashVersion": hashVersion, "fields": fields})
	return []byte(s), err
}

func buildLeaf(row Row, key []byte) (leaf, error) {
	l := leaf{row: row, fieldValues: row.Fields, salts: map[string]string{}, commitments: map[string]string{}}
	for _, f := range FieldsFor(row.HashVersion) {
		salt := fieldSalt(key, row.Hash, f)
		c, err := fieldCommitment(f, salt, row.Fields[f])
		if err != nil {
			return leaf{}, fmt.Errorf("checkpoint: row %s field %s: %w", row.ID, f, err)
		}
		l.salts[f], l.commitments[f] = salt, c
	}
	pre, err := leafPreimage(row.ID, row.Hash, row.HashVersion, l.commitments)
	if err != nil {
		return leaf{}, err
	}
	l.hash = LeafHash(pre)
	return l, nil
}

// loadLeaves returns the log's leaves in order, bounded by row timestamp, and
// cut to limit when limit >= 0.
func (lg Log) loadLeaves(ctx context.Context, since, until *int64, limit int64) ([]leaf, error) {
	if lg.Source == nil {
		return nil, errors.New("checkpoint: log has no source")
	}
	if len(lg.SaltKey) == 0 {
		return nil, errors.New("checkpoint: log has no salt key")
	}
	rows, err := lg.Source.Rows(ctx)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: read rows: %w", err)
	}
	kept := make([]Row, 0, len(rows))
	for _, r := range rows {
		if r.Hash == "" || (since != nil && r.TimestampMs < *since) || (until != nil && r.TimestampMs > *until) {
			continue
		}
		kept = append(kept, r)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].TimestampMs != kept[j].TimestampMs {
			return kept[i].TimestampMs < kept[j].TimestampMs
		}
		return kept[i].ID < kept[j].ID
	})
	if limit >= 0 && int64(len(kept)) > limit {
		kept = kept[:limit]
	}
	out := make([]leaf, 0, len(kept))
	for _, r := range kept {
		l, err := buildLeaf(r, lg.SaltKey)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func leafHashes(ls []leaf) [][]byte {
	out := make([][]byte, len(ls))
	for i, l := range ls {
		out[i] = l.hash
	}
	return out
}

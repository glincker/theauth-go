package checkpoint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// A head checkpoint is a signed list of the last position of every audit chain: for each chain key
// (the organization id, empty for global events) the highest seq and the hash of that row. A
// verifier that walks exported rows cannot tell that rows were cut off the end of a chain, because
// every remaining row still links to the one before it. Keep a head checkpoint somewhere the log's
// writer cannot rewrite, and CheckHeadCheckpoint reports a chain that is now shorter, or whose row at
// the signed seq has a different hash.
//
// It is signed with the same Ed25519 keys and Signer as a Merkle Checkpoint, so one published
// public key verifies both. The signed bytes are headSignDomain followed by the canonical JSON
// (sorted keys, no whitespace) of {version, alg, keyId, timestamp, heads}, where heads is a list of
// {chainKey, seq, hash} sorted by chainKey and the signature is base64url without padding.

const (
	headSignDomain = "theauth.audit.head.v1\n"
	headVersion    = 1
	// ReasonChainTruncated means a chain has fewer rows than the signed head, or is missing.
	ReasonChainTruncated Reason = "chain_truncated"
	// ReasonHeadMismatch means the row at the signed seq has a different hash.
	ReasonHeadMismatch Reason = "head_mismatch"
)

// ChainHead is the last position of one chain at signing time.
type ChainHead struct {
	// ChainKey is the organization id, or empty for the global chain.
	ChainKey string `json:"chainKey"`
	// Seq is the highest chain sequence number, counting from 1.
	Seq int64 `json:"seq"`
	// Hash is the lowercase hex chain hash of the row at Seq.
	Hash string `json:"hash"`
}

// HeadCheckpoint is a signed set of chain heads.
type HeadCheckpoint struct {
	Version int `json:"version"`
	// Alg is always "Ed25519".
	Alg   string `json:"alg"`
	KeyID string `json:"keyId"`
	// Timestamp is the signing time in milliseconds since the epoch.
	Timestamp int64       `json:"timestamp"`
	Heads     []ChainHead `json:"heads"`
	// Signature is the base64url Ed25519 signature over the other fields.
	Signature string `json:"signature"`
}

// UnmarshalJSON rejects a head checkpoint with a missing or null field.
func (h *HeadCheckpoint) UnmarshalJSON(data []byte) error {
	if err := requireKeys(data, "version", "alg", "keyId", "timestamp", "heads", "signature"); err != nil {
		return err
	}
	type plain HeadCheckpoint
	return json.Unmarshal(data, (*plain)(h))
}

// HeadOptions configures CreateHeadCheckpoint.
type HeadOptions struct {
	Signer Signer
	// Now overrides the clock (tests).
	Now time.Time
}

// ChainHeads reads the current head of every chain by scanning the chained events of a store.
// pageSize zero means 500. Unchained events are skipped.
func ChainHeads(ctx context.Context, st EventQuerier, pageSize int) ([]ChainHead, error) {
	m, _, err := scanHeads(ctx, st, pageSize, nil)
	if err != nil {
		return nil, err
	}
	out := make([]ChainHead, 0, len(m))
	for _, h := range m {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChainKey < out[j].ChainKey })
	return out, nil
}

// scanHeads returns the highest row per chain, plus the hash at each seq listed in want (keyed by
// chain key), so a check needs one pass and no per row memory.
func scanHeads(ctx context.Context, st EventQuerier, pageSize int, want map[string]int64) (map[string]ChainHead, map[string]string, error) {
	if pageSize <= 0 {
		pageSize = 500
	}
	heads := map[string]ChainHead{}
	atSeq := map[string]string{}
	after := ""
	for {
		events, next, err := st.QueryAuditEvents(ctx, models.AuditQuery{Limit: pageSize, After: after})
		if err != nil {
			return nil, nil, err
		}
		for _, e := range events {
			if e.Hash == "" || e.ChainSeq == 0 {
				continue
			}
			key, seq := audit.ChainKey(e), int64(e.ChainSeq)
			if cur, ok := heads[key]; !ok || seq > cur.Seq {
				heads[key] = ChainHead{ChainKey: key, Seq: seq, Hash: e.Hash}
			}
			if w, ok := want[key]; ok && w == seq {
				atSeq[key] = e.Hash
			}
		}
		if next == "" || next == after || len(events) == 0 {
			return heads, atSeq, nil
		}
		after = next
	}
}

func headSignedBytes(h HeadCheckpoint) ([]byte, error) {
	heads := make([]any, len(h.Heads))
	for i, c := range h.Heads {
		heads[i] = map[string]any{"chainKey": c.ChainKey, "seq": c.Seq, "hash": c.Hash}
	}
	s, err := CanonicalJSON(map[string]any{
		"version": h.Version, "alg": h.Alg, "keyId": h.KeyID, "timestamp": h.Timestamp, "heads": heads,
	})
	if err != nil {
		return nil, err
	}
	return []byte(headSignDomain + s), nil
}

// CreateHeadCheckpoint signs the current head of every chain in st. A store with no chained rows
// gives a checkpoint with no heads.
func CreateHeadCheckpoint(ctx context.Context, st EventQuerier, opts HeadOptions) (HeadCheckpoint, error) {
	if opts.Signer == nil {
		return HeadCheckpoint{}, fmt.Errorf("checkpoint: no signer")
	}
	heads, err := ChainHeads(ctx, st, 0)
	if err != nil {
		return HeadCheckpoint{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	h := HeadCheckpoint{
		Version: headVersion, Alg: algEd25519, KeyID: opts.Signer.KeyID(), Timestamp: now.UnixMilli(), Heads: heads,
	}
	msg, err := headSignedBytes(h)
	if err != nil {
		return HeadCheckpoint{}, err
	}
	sig, err := opts.Signer.Sign(msg)
	if err != nil {
		return HeadCheckpoint{}, fmt.Errorf("checkpoint: sign: %w", err)
	}
	if len(sig) != signatureBytes {
		return HeadCheckpoint{}, errors.New("checkpoint: signer did not return a 64 byte Ed25519 signature")
	}
	h.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return h, nil
}

func headWellFormed(h HeadCheckpoint) bool {
	if h.Version != headVersion || h.Timestamp < 0 || h.Timestamp > maxSafeInteger || h.Heads == nil {
		return false
	}
	for i, c := range h.Heads {
		if c.Seq < 1 || c.Seq > maxSafeInteger || !isHashHex(c.Hash) {
			return false
		}
		if i > 0 && h.Heads[i-1].ChainKey >= c.ChainKey {
			return false
		}
	}
	return true
}

// VerifyHeadCheckpoint verifies the signature and shape of a head checkpoint offline. It rejects any
// algorithm other than Ed25519 and any keyId no supplied key carries.
func VerifyHeadCheckpoint(h HeadCheckpoint, keys ...PublicKey) Outcome {
	if !headWellFormed(h) {
		return fail(ReasonMalformed)
	}
	if h.Alg != algEd25519 {
		return fail(ReasonUnsupportedAlg)
	}
	msg, err := headSignedBytes(h)
	if err != nil {
		return fail(ReasonMalformed)
	}
	return verifySignature(h.KeyID, h.Signature, msg, keys)
}

// HeadCheck is the result of CheckHeadCheckpoint.
type HeadCheck struct {
	Outcome
	// ChainKey is the first chain that failed, empty for the global chain. Meaningful only when
	// Valid is false and Reason is ReasonChainTruncated or ReasonHeadMismatch.
	ChainKey string
}

// CheckHeadCheckpoint verifies the checkpoint signature, then compares it with the live log: every
// signed chain must still reach its signed seq with the signed hash. Chains and rows added after
// signing are fine. Run the store's VerifyAuditChain as well, since this check looks only at the
// signed positions.
func CheckHeadCheckpoint(ctx context.Context, st EventQuerier, h HeadCheckpoint, keys ...PublicKey) (HeadCheck, error) {
	if o := VerifyHeadCheckpoint(h, keys...); !o.Valid {
		return HeadCheck{Outcome: o}, nil
	}
	want := make(map[string]int64, len(h.Heads))
	for _, c := range h.Heads {
		want[c.ChainKey] = c.Seq
	}
	heads, atSeq, err := scanHeads(ctx, st, 0, want)
	if err != nil {
		return HeadCheck{}, err
	}
	for _, c := range h.Heads {
		if cur, ok := heads[c.ChainKey]; !ok || cur.Seq < c.Seq {
			return HeadCheck{Outcome: fail(ReasonChainTruncated), ChainKey: c.ChainKey}, nil
		}
		if !sameHex(atSeq[c.ChainKey], c.Hash) {
			return HeadCheck{Outcome: fail(ReasonHeadMismatch), ChainKey: c.ChainKey}, nil
		}
	}
	return HeadCheck{Outcome: OK()}, nil
}

package checkpoint

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateOptions configures CreateCheckpoint.
type CreateOptions struct {
	Signer Signer
	// Since covers only rows with timestamp at or after this. Recorded and signed.
	Since *time.Time
	// Until covers only rows with timestamp at or before this. Use it to leave out rows that may still be arriving.
	Until *time.Time
	// Now overrides the clock (tests).
	Now time.Time
	// Store, when set, receives the checkpoint after signing.
	Store Store
}

func msPtr(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	v := t.UnixMilli()
	return &v
}

func rootHex(ls []leaf) string { return hex.EncodeToString(MerkleRoot(leafHashes(ls))) }

func sameHex(a, b string) bool {
	if !isHashHex(a) || !isHashHex(b) {
		return false
	}
	x, _ := hex.DecodeString(a)
	y, _ := hex.DecodeString(b)
	return eq(x, y)
}

// CreateCheckpoint builds a Merkle tree over every chained audit row and signs
// its head. An empty log gives a size 0 checkpoint.
func CreateCheckpoint(ctx context.Context, lg Log, opts CreateOptions) (Checkpoint, error) {
	if opts.Signer == nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: no signer")
	}
	since, until := msPtr(opts.Since), msPtr(opts.Until)
	ls, err := lg.loadLeaves(ctx, since, until, -1)
	if err != nil {
		return Checkpoint{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	cp, err := signCheckpoint(opts.Signer, Checkpoint{
		Version: checkpointVersion, Alg: algEd25519, KeyID: opts.Signer.KeyID(), Size: int64(len(ls)),
		RootHash: rootHex(ls), Timestamp: now.UnixMilli(), Since: since, Until: until,
	})
	if err != nil {
		return Checkpoint{}, err
	}
	if opts.Store != nil {
		if err := opts.Store.Put(ctx, cp); err != nil {
			return Checkpoint{}, err
		}
	}
	return cp, nil
}

// leavesMatching rebuilds the first cp.Size leaves and confirms they still
// hash to the checkpoint root. A mismatch means the log was rewritten, shrunk,
// or a row landed inside the covered range after the checkpoint.
func (lg Log) leavesMatching(ctx context.Context, cp Checkpoint) ([]leaf, error) {
	if !wellFormed(cp) {
		return nil, newErr(ErrInvalidCheckpoint, "malformed checkpoint")
	}
	ls, err := lg.loadLeaves(ctx, cp.Since, cp.Until, cp.Size)
	if err != nil {
		return nil, err
	}
	if int64(len(ls)) < cp.Size {
		return nil, newErr(ErrLogMismatch, "the log has fewer rows than the checkpoint committed to")
	}
	if !sameHex(rootHex(ls), cp.RootHash) {
		return nil, newErr(ErrLogMismatch, "the log no longer matches the checkpoint root")
	}
	return ls, nil
}

// CreateInclusionProof proves a row is a leaf of the tree the checkpoint
// committed to. Rows added later do not matter.
func CreateInclusionProof(ctx context.Context, lg Log, rowID string, cp Checkpoint) (InclusionProof, error) {
	ls, err := lg.leavesMatching(ctx, cp)
	if err != nil {
		return InclusionProof{}, err
	}
	idx := indexOf(ls, rowID)
	if idx < 0 {
		return InclusionProof{}, newErr(ErrRowNotFound, "the row is not covered by this checkpoint")
	}
	path, err := InclusionPath(leafHashes(ls), idx)
	if err != nil {
		return InclusionProof{}, err
	}
	return InclusionProof{
		Version: 1, RowID: rowID, LeafIndex: int64(idx), TreeSize: cp.Size,
		LeafHash: hex.EncodeToString(ls[idx].hash), Path: hexList(path),
	}, nil
}

func indexOf(ls []leaf, rowID string) int {
	for i, l := range ls {
		if l.row.ID == rowID {
			return i
		}
	}
	return -1
}

func proofShapeOK(p InclusionProof) bool {
	if p.Version != 1 || p.LeafIndex < 0 || p.LeafIndex > maxSafeInteger || p.TreeSize < 0 || p.TreeSize > maxSafeInteger || !isHashHex(p.LeafHash) || p.Path == nil {
		return false
	}
	for _, h := range p.Path {
		if !isHashHex(h) {
			return false
		}
	}
	return true
}

// VerifyInclusionProof checks offline that the signed checkpoint is genuine and
// the proof's leaf hash is in its tree.
func VerifyInclusionProof(p InclusionProof, cp Checkpoint, keys ...PublicKey) Outcome {
	if o := VerifyCheckpoint(cp, keys...); !o.Valid {
		return o
	}
	if !proofShapeOK(p) {
		return fail(ReasonMalformed)
	}
	if p.TreeSize != cp.Size {
		return fail(ReasonSizeMismatch)
	}
	leafHash, _ := hex.DecodeString(p.LeafHash)
	root, _ := hex.DecodeString(cp.RootHash)
	path, ok := decodeHexList(p.Path)
	if !ok {
		return fail(ReasonMalformed)
	}
	if !VerifyInclusionPath(leafHash, p.LeafIndex, p.TreeSize, path, root) {
		return fail(ReasonBadProof)
	}
	return OK()
}

// CreateConsistencyProof proves newer extends older without rewriting any
// earlier row. It needs the log because a checkpoint holds only the root.
func CreateConsistencyProof(ctx context.Context, lg Log, older, newer Checkpoint) (ConsistencyProof, error) {
	if !wellFormed(older) || !wellFormed(newer) {
		return ConsistencyProof{}, newErr(ErrInvalidCheckpoint, "malformed checkpoint")
	}
	if older.Size > newer.Size {
		return ConsistencyProof{}, newErr(ErrInvalidOrder, "the older checkpoint is larger than the newer one")
	}
	if !sameBound(older.Since, newer.Since) {
		return ConsistencyProof{}, newErr(ErrScopeMismatch, "the checkpoints cover different ranges")
	}
	ls, err := lg.leavesMatching(ctx, newer)
	if err != nil {
		return ConsistencyProof{}, err
	}
	if !sameHex(rootHex(ls[:older.Size]), older.RootHash) {
		return ConsistencyProof{}, newErr(ErrLogMismatch, "the older checkpoint is not a prefix of the current log")
	}
	path, err := ConsistencyPath(leafHashes(ls), int(older.Size))
	if err != nil {
		return ConsistencyProof{}, err
	}
	return ConsistencyProof{Version: 1, OldSize: older.Size, NewSize: newer.Size, Path: hexList(path)}, nil
}

func sameBound(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// VerifyConsistencyProof checks offline that newer is an append only extension
// of older. Both signatures are checked.
func VerifyConsistencyProof(p ConsistencyProof, older, newer Checkpoint, keys ...PublicKey) Outcome {
	if o := VerifyCheckpoint(older, keys...); !o.Valid {
		return o
	}
	if o := VerifyCheckpoint(newer, keys...); !o.Valid {
		return o
	}
	if p.Version != 1 || p.Path == nil {
		return fail(ReasonMalformed)
	}
	path, ok := decodeHexList(p.Path)
	if !ok {
		return fail(ReasonMalformed)
	}
	if p.OldSize != older.Size || p.NewSize != newer.Size {
		return fail(ReasonSizeMismatch)
	}
	if !sameBound(older.Since, newer.Since) {
		return fail(ReasonScopeMismatch)
	}
	oldRoot, _ := hex.DecodeString(older.RootHash)
	newRoot, _ := hex.DecodeString(newer.RootHash)
	if !VerifyConsistencyPath(older.Size, newer.Size, oldRoot, newRoot, path) {
		return fail(ReasonBadProof)
	}
	return OK()
}

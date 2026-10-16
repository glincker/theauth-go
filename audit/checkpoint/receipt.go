package checkpoint

import (
	"context"
	"encoding/hex"
	"slices"
)

// CreateReceipt builds a receipt for one row against a checkpoint that already
// covers it. reveal names the fields to disclose; every other field stays a
// salted commitment.
func CreateReceipt(ctx context.Context, lg Log, rowID string, cp Checkpoint, reveal []string) (Receipt, error) {
	ls, err := lg.leavesMatching(ctx, cp)
	if err != nil {
		return Receipt{}, err
	}
	idx := indexOf(ls, rowID)
	if idx < 0 {
		return Receipt{}, newErr(ErrRowNotFound, "the row is not covered by this checkpoint")
	}
	l := ls[idx]
	allowed := FieldsFor(l.row.HashVersion)
	for _, name := range reveal {
		if !slices.Contains(allowed, name) {
			return Receipt{}, newErr(ErrInvalidField, "field %q cannot be revealed for this row", name)
		}
	}
	revealed := map[string]RevealedField{}
	commitments := map[string]string{}
	for _, name := range allowed {
		if slices.Contains(reveal, name) {
			revealed[name] = RevealedField{Value: l.fieldValues[name], Salt: l.salts[name]}
		} else {
			commitments[name] = l.commitments[name]
		}
	}
	path, err := InclusionPath(leafHashes(ls), idx)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		Version:  1,
		Decision: Decision{RowID: rowID, RowHash: l.row.Hash, HashVersion: l.row.HashVersion, Revealed: revealed, Commitments: commitments},
		Proof: InclusionProof{
			Version: 1, RowID: rowID, LeafIndex: int64(idx), TreeSize: cp.Size,
			LeafHash: hex.EncodeToString(l.hash), Path: hexList(path),
		},
		Checkpoint: cp,
	}, nil
}

// VerifyReceipt verifies a receipt offline: the checkpoint signature, that the
// revealed values match their commitments, and that the resulting leaf is in
// the checkpoint tree.
func VerifyReceipt(r Receipt, keys ...PublicKey) Outcome {
	d := r.Decision
	if r.Version != 1 || d.Revealed == nil || d.Commitments == nil || d.RowID != r.Proof.RowID {
		return fail(ReasonMalformed)
	}
	allowed := FieldsFor(d.HashVersion)
	if len(d.Revealed)+len(d.Commitments) != len(allowed) {
		return fail(ReasonMalformed)
	}
	commitments := make(map[string]string, len(allowed))
	for name, hidden := range d.Commitments {
		if !slices.Contains(allowed, name) || !isHashHex(hidden) {
			return fail(ReasonMalformed)
		}
		commitments[name] = hidden
	}
	for name, f := range d.Revealed {
		if !slices.Contains(allowed, name) || !isHashHex(f.Salt) {
			return fail(ReasonMalformed)
		}
		if _, dup := commitments[name]; dup {
			return fail(ReasonMalformed)
		}
		c, err := fieldCommitment(name, f.Salt, f.Value)
		if err != nil {
			return fail(ReasonBadCommitment)
		}
		commitments[name] = c
	}
	pre, err := leafPreimage(d.RowID, d.RowHash, d.HashVersion, commitments)
	if err != nil {
		return fail(ReasonMalformed)
	}
	want := LeafHash(pre)
	got, err := hex.DecodeString(r.Proof.LeafHash)
	if err != nil || !isHashHex(r.Proof.LeafHash) || !eq(want, got) {
		return fail(ReasonLeafMismatch)
	}
	return VerifyInclusionProof(r.Proof, r.Checkpoint, keys...)
}

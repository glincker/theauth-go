package memory

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
)

// ChainSupported reports that this backend keeps the tamper-evident audit hash chain, with the
// same row format and verifier as sqlite, postgres and mysql. The audit log is a ring buffer of
// 10000 rows, so the oldest rows are evicted on a busy process. Verification anchors on the first
// retained row of each chain, and a signed head checkpoint (audit/checkpoint) catches tail loss.
func (s *Store) ChainSupported() bool { return true }

// chainEvent stamps e with its chain position and returns the entry to keep next to it. The caller
// holds v.mu.
func (v *v10State) chainEvent(e *theauth.AuditEvent) (audit.ChainEntry, error) {
	if v.auditSecret == nil {
		secret, err := audit.NewSecret()
		if err != nil {
			return audit.ChainEntry{}, err
		}
		v.auditSecret = secret
		v.auditHeads = map[string]audit.ChainHead{}
	}
	// Own the maps and slices, so a caller changing them later cannot alter what was hashed.
	e.Metadata = cloneJSONMap(e.Metadata)
	e.InputProvenance = cloneJSONMap(e.InputProvenance)
	e.DelegationChain = slices.Clone(e.DelegationChain)
	key := audit.ChainKey(*e)
	head := v.auditHeads[key]
	ps, err := v.auditRotation.Resolve(context.Background(), v.auditSecret, memPeriods{v}, []time.Time{e.CreatedAt})
	if err != nil {
		return audit.ChainEntry{}, err
	}
	ce, err := audit.BuildChainEntryWith(*e, ps, head)
	if err != nil {
		return audit.ChainEntry{}, err
	}
	e.ChainSeq, e.PrevHash, e.Hash = uint64(ce.Payload.Seq), head.Hash, ce.Hash
	v.auditHeads[key] = audit.ChainHead{Seq: ce.Payload.Seq, Hash: ce.Hash}
	return ce, nil
}

// VerifyAuditChain walks every chain in seq order and reports the first mismatched row. Stored
// fields are rehashed from the live event, so an edit to a row after it was written is a break.
func (s *Store) VerifyAuditChain(_ context.Context) (theauth.AuditChainResult, error) {
	v := s.auditState()
	v.mu.Lock()
	idx := make([]int, len(v.auditRing))
	for i := range idx {
		idx[i] = i
	}
	rows := make([]audit.ChainRow, 0, len(idx))
	for _, i := range idx {
		rows = append(rows, v.chainRowAt(i))
	}
	keys := audit.PseudonymKeys{Stable: slices.Clone(v.auditSecret), Periods: map[int64][]byte{}}
	for p, sec := range v.auditPeriods {
		keys.Periods[p] = slices.Clone(sec)
	}
	v.mu.Unlock()
	sort.SliceStable(rows, func(a, b int) bool {
		pa, pb := rows[a].Payload, rows[b].Payload
		if pa.ChainKey != pb.ChainKey {
			return pa.ChainKey < pb.ChainKey
		}
		return pa.Seq < pb.Seq
	})
	n := 0
	return audit.VerifyChainRowsAnchoredKeys(func() (audit.ChainRow, bool, error) {
		if n >= len(rows) {
			return audit.ChainRow{}, false, nil
		}
		n++
		return rows[n-1], true, nil
	}, keys, 0)
}

// chainRowAt rebuilds the hashed payload of ring slot i from the live event, keeping the stored
// pseudonyms and session, and pairs it with the stored hash. The caller holds v.mu.
func (v *v10State) chainRowAt(i int) audit.ChainRow {
	e, ce := v.auditRing[i], v.auditChain[i]
	p := ce.Payload
	p.ID = e.ID.String()
	p.Action, p.TargetType, p.TargetID = e.Action, e.TargetType, e.TargetID
	p.IP, p.UserAgent, p.PolicyVersion = e.IP, e.UserAgent, e.PolicyVersion
	p.CreatedAt = e.CreatedAt.UTC().UnixMicro()
	p.Metadata, _ = audit.MarshalOr(e.Metadata, "{}")
	p.DelegationChain, _ = audit.MarshalOr(e.DelegationChain, "[]")
	p.InputProvenance, _ = audit.MarshalOr(e.InputProvenance, "{}")
	r := audit.ChainRow{
		Payload: p, Hash: e.Hash,
		RawSubject: e.SubjectID, RawActor: e.ActorID, RawApprover: e.ApproverID,
	}
	if e.ActorUserID != nil {
		r.RawActorUser = e.ActorUserID.String()
	}
	if e.OrganizationID != nil {
		r.RawOrg = e.OrganizationID.String()
	}
	if e.ActorSessionID != nil {
		r.RawSession = e.ActorSessionID.String()
	}
	if e.Hash != ce.Hash || e.ChainSeq != uint64(p.Seq) || e.PrevHash != p.Prev {
		r.ExtraBreak = "hash_mismatch"
	}
	return r
}

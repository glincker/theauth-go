package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// ChainHashVersion is bumped when the hashed field set changes. It is part of
// the hashed payload, so rows of different versions never collide.
const ChainHashVersion = 1

// ChainPayload is the exact structure hashed for one audit row. Field order fixes the JSON key
// order, and every backend hashes this same shape. storage/sqlite is a separate module with a
// byte-identical copy; TestChainHashGoldenVector here and its twin there pin both to one digest.
// Personal ids are hashed as keyed pseudonyms, so erasing a user keeps the chain intact.
type ChainPayload struct {
	V               int    `json:"v"`
	ChainKey        string `json:"chainKey"`
	Seq             int64  `json:"seq"`
	Prev            string `json:"prev"`
	ID              string `json:"id"`
	Org             string `json:"org"`
	ActorUserPseudo string `json:"actorUserPseudonym"`
	ActorSession    string `json:"actorSession"`
	Action          string `json:"action"`
	TargetType      string `json:"targetType"`
	TargetID        string `json:"targetId"`
	Metadata        string `json:"metadata"`
	IP              string `json:"ip"`
	UserAgent       string `json:"userAgent"`
	CreatedAt       int64  `json:"createdAt"`
	SubjectPseudo   string `json:"subjectPseudonym"`
	ActorPseudo     string `json:"actorPseudonym"`
	PolicyVersion   string `json:"policyVersion"`
	ApproverPseudo  string `json:"approverPseudonym"`
	DelegationChain string `json:"delegationChain"`
	InputProvenance string `json:"inputProvenance"`
}

// RowHash returns the hex SHA-256 of the payload at the current hash version.
func RowHash(p ChainPayload) (string, error) {
	p.V = ChainHashVersion
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Pseudonym is HMAC-SHA256(secret, "theauth.audit.pseudonym.v1:" + id) in hex.
// Empty ids stay empty.
func Pseudonym(secret []byte, id string) string {
	if id == "" {
		return ""
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("theauth.audit.pseudonym.v1:" + id))
	return hex.EncodeToString(m.Sum(nil))
}

// NewSecret returns a fresh 32-byte installation secret for pseudonyms.
func NewSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate audit secret: %w", err)
	}
	return b, nil
}

// MarshalOr JSON-encodes v, returning empty when it encodes to null.
func MarshalOr(v any, empty string) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(raw) == "null" {
		return empty, nil
	}
	return string(raw), nil
}

// ChainHead is the last position of one chain.
type ChainHead struct {
	Seq  int64
	Hash string
}

// ChainEntry is one event prepared for a chained insert: the exact strings
// to store (they are what is hashed) plus the computed hash.
type ChainEntry struct {
	Payload ChainPayload
	Hash    string
	// Metadata, DelegationChain and InputProvenance are stored verbatim as JSON text, so the hash
	// recomputes exactly.
	Metadata        string
	DelegationChain string
	InputProvenance string
	CreatedAtMicro  int64
}

// ChainKey returns the chain an event belongs to: its organization id, or
// empty for global events.
func ChainKey(e models.AuditEvent) string {
	if e.OrganizationID == nil {
		return ""
	}
	return e.OrganizationID.String()
}

// BuildChainEntry computes the stored strings and hash for the row at head+1 of a chain. It defines
// the hash input for every backend.
func BuildChainEntry(e models.AuditEvent, secret []byte, head ChainHead) (ChainEntry, error) {
	meta, err := MarshalOr(e.Metadata, "{}")
	if err != nil {
		return ChainEntry{}, fmt.Errorf("marshal audit metadata: %w", err)
	}
	chain, err := MarshalOr(e.DelegationChain, "[]")
	if err != nil {
		return ChainEntry{}, fmt.Errorf("marshal delegation chain: %w", err)
	}
	prov, err := MarshalOr(e.InputProvenance, "{}")
	if err != nil {
		return ChainEntry{}, fmt.Errorf("marshal input provenance: %w", err)
	}
	created := e.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	key := ChainKey(e)
	p := ChainPayload{
		ChainKey: key, Seq: head.Seq + 1, Prev: head.Hash, ID: e.ID.String(), Org: key,
		Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID, Metadata: meta,
		IP: e.IP, UserAgent: e.UserAgent, CreatedAt: created.UTC().UnixMicro(),
		SubjectPseudo: Pseudonym(secret, e.SubjectID), ActorPseudo: Pseudonym(secret, e.ActorID),
		PolicyVersion: e.PolicyVersion, ApproverPseudo: Pseudonym(secret, e.ApproverID),
		DelegationChain: chain, InputProvenance: prov,
	}
	if e.ActorUserID != nil {
		p.ActorUserPseudo = Pseudonym(secret, e.ActorUserID.String())
	}
	if e.ActorSessionID != nil {
		p.ActorSession = e.ActorSessionID.String()
	}
	h, err := RowHash(p)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("hash audit event: %w", err)
	}
	return ChainEntry{Payload: p, Hash: h, Metadata: meta, DelegationChain: chain,
		InputProvenance: prov, CreatedAtMicro: p.CreatedAt}, nil
}

// ChainRow is one stored chained row as read back for verification.
type ChainRow struct {
	Payload ChainPayload
	Hash    string
	// Raw ids as currently stored. Empty after erasure.
	RawActorUser, RawSubject, RawActor, RawApprover string
	// RawOrg and RawSession are the foreign-key columns (empty when null or deleted). When present
	// they must agree with the hashed values.
	RawOrg, RawSession string
	// ExtraBreak, when set, is a backend-detected inconsistency reported as the break reason after the
	// hash verifies.
	ExtraBreak string
}

// VerifyChainRows walks rows ordered by (chain key, seq). unchained counts the pre-chain rows.
// secret may be nil when no chained write happened.
func VerifyChainRows(next func() (ChainRow, bool, error), secret []byte, unchained int) (models.AuditChainResult, error) {
	res := models.AuditChainResult{Supported: true, Unchained: unchained, OK: true}
	var (
		curKey   string
		started  bool
		wantSeq  int64
		wantPrev string
	)
	for {
		r, ok, err := next()
		if err != nil {
			return res, err
		}
		if !ok {
			return res, nil
		}
		p := r.Payload
		if !started || p.ChainKey != curKey {
			curKey, started, wantSeq, wantPrev = p.ChainKey, true, 1, ""
		}
		res.Checked++
		brk := func(reason string) (models.AuditChainResult, error) {
			res.OK = false
			res.FirstBreak = &models.AuditChainBreak{ChainKey: p.ChainKey, RowID: p.ID, Seq: p.Seq, Reason: reason}
			return res, nil
		}
		if p.Seq != wantSeq {
			return brk("seq_gap")
		}
		if p.Prev != wantPrev {
			return brk("prev_hash_mismatch")
		}
		want, err := RowHash(p)
		if err != nil {
			return res, fmt.Errorf("verify audit chain: %w", err)
		}
		if want != r.Hash {
			return brk("hash_mismatch")
		}
		if (r.RawOrg != "" && r.RawOrg != p.ChainKey) || (r.RawSession != "" && r.RawSession != p.ActorSession) {
			return brk("hash_mismatch")
		}
		if r.ExtraBreak != "" {
			return brk(r.ExtraBreak)
		}
		erased := false
		for _, c := range []struct{ raw, pseudo string }{
			{r.RawActorUser, p.ActorUserPseudo}, {r.RawSubject, p.SubjectPseudo},
			{r.RawActor, p.ActorPseudo}, {r.RawApprover, p.ApproverPseudo},
		} {
			switch {
			case c.raw == "" && c.pseudo != "":
				erased = true
			case c.raw != "" && secret != nil && Pseudonym(secret, c.raw) != c.pseudo:
				return brk("pseudonym_mismatch")
			}
		}
		if erased {
			res.Erased++
		}
		wantSeq++
		wantPrev = r.Hash
	}
}

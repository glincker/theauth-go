package sqlite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// auditHashVersion is bumped when the hashed field set changes. It is part
// of the hashed payload, so rows of different versions never collide.
const auditHashVersion = 1

// ChainSupported reports that this backend keeps a tamper-evident audit hash
// chain. The memory backend returns false. postgres and mysql chain with the
// same hash input (internal/audit.ChainPayload); the golden vector test pins both.
func (s *Store) ChainSupported() bool { return true }

// auditChainPayload is the exact structure hashed for one row. Struct field
// order fixes the JSON key order; the string columns are hashed as stored so
// a read-back recomputes the same bytes.
//
// The personal ids (actor user, subject, actor, approver) are hashed as keyed
// pseudonyms, never raw. Erasure (DeleteUserCascade) blanks the raw columns
// and keeps the pseudonym columns, so the hash still verifies afterwards.
// Tradeoff: a pseudonym is linkable by whoever holds the installation secret
// (theauth_audit_secrets), so deleting that secret is a further erasure
// option. It is deliberately not implemented here (no key shredding).
type auditChainPayload struct {
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

func auditRowHash(p auditChainPayload) (string, error) {
	p.V = auditHashVersion
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// auditPseudonym is HMAC-SHA256(secret, id) in hex; empty ids stay empty.
func auditPseudonym(secret []byte, id string) string {
	if id == "" {
		return ""
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("theauth.audit.pseudonym.v1:" + id))
	return hex.EncodeToString(m.Sum(nil))
}

// auditSecret returns the installation secret, creating it on first use.
func (s *Store) auditSecret(ctx context.Context, q DBTX) ([]byte, error) {
	var secret []byte
	err := q.QueryRowContext(ctx, s.q(`SELECT secret FROM theauth_audit_secrets WHERE id = 1`)).Scan(&secret)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("generate audit secret: %w", err)
	}
	if _, err := q.ExecContext(ctx, s.q(
		`INSERT INTO theauth_audit_secrets (id, secret, created_at) VALUES (1, ?, ?)
ON CONFLICT (id) DO NOTHING`), fresh, toMicro(time.Now())); err != nil {
		return nil, err
	}
	// Re-read so a concurrent creator's value wins consistently.
	if err := q.QueryRowContext(ctx, s.q(`SELECT secret FROM theauth_audit_secrets WHERE id = 1`)).Scan(&secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// AuditChainBreak, AuditChainResult: see theauth.AuditChainResult.
type (
	AuditChainBreak  = theauth.AuditChainBreak
	AuditChainResult = theauth.AuditChainResult
)

// VerifyAuditChain walks every chain in seq order and reports the first row
// whose link or hash does not match. Rows written before migration 0017 have
// no chain position and are counted as Unchained, not as failures. Rows whose
// raw ids were erased still verify through the stored pseudonyms and are
// counted in Erased. Where a raw id is still present it must match its
// pseudonym, so editing a raw column is reported as pseudonym_mismatch.
func (s *Store) VerifyAuditChain(ctx context.Context) (AuditChainResult, error) {
	res := AuditChainResult{Supported: true}
	row := s.db.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM theauth_audit_events WHERE chain_seq IS NULL`))
	if err := row.Scan(&res.Unchained); err != nil {
		return res, wrap("verify audit chain", err)
	}
	secret, err := s.auditSecretIfPresent(ctx)
	if err != nil {
		return res, wrap("verify audit chain", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT id, COALESCE(organization_id, ''), COALESCE(actor_user_id, ''), COALESCE(actor_session_id, ''),
       action, target_type, target_id, metadata, ip, user_agent, created_at,
       subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
       actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
       chain_key, chain_seq, prev_hash, hash
FROM theauth_audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_key, chain_seq`))
	if err != nil {
		return res, wrap("verify audit chain", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		curKey   string
		started  bool
		wantSeq  int64
		wantPrev string
	)
	res.OK = true
	for rows.Next() {
		var (
			p                                               auditChainPayload
			hash                                            string
			rawActorUser, rawSubject, rawActor, rawApprover string
		)
		if err := rows.Scan(&p.ID, &p.Org, &rawActorUser, &p.ActorSession, &p.Action, &p.TargetType, &p.TargetID,
			&p.Metadata, &p.IP, &p.UserAgent, &p.CreatedAt, &rawSubject, &rawActor, &p.PolicyVersion,
			&rawApprover, &p.DelegationChain, &p.InputProvenance,
			&p.ActorUserPseudo, &p.SubjectPseudo, &p.ActorPseudo, &p.ApproverPseudo,
			&p.ChainKey, &p.Seq, &p.Prev, &hash); err != nil {
			return res, wrap("verify audit chain", err)
		}
		if !started || p.ChainKey != curKey {
			curKey, started, wantSeq, wantPrev = p.ChainKey, true, 1, ""
		}
		res.Checked++
		brk := func(reason string) (AuditChainResult, error) {
			res.OK = false
			res.FirstBreak = &AuditChainBreak{ChainKey: p.ChainKey, RowID: p.ID, Seq: p.Seq, Reason: reason}
			return res, nil
		}
		if p.Seq != wantSeq {
			return brk("seq_gap")
		}
		if p.Prev != wantPrev {
			return brk("prev_hash_mismatch")
		}
		want, err := auditRowHash(p)
		if err != nil {
			return res, fmt.Errorf("verify audit chain: %w", err)
		}
		if want != hash {
			return brk("hash_mismatch")
		}
		erased := false
		for _, c := range []struct{ raw, pseudo string }{
			{rawActorUser, p.ActorUserPseudo}, {rawSubject, p.SubjectPseudo},
			{rawActor, p.ActorPseudo}, {rawApprover, p.ApproverPseudo},
		} {
			switch {
			case c.raw == "" && c.pseudo != "":
				erased = true
			case c.raw != "" && secret != nil && auditPseudonym(secret, c.raw) != c.pseudo:
				return brk("pseudonym_mismatch")
			}
		}
		if erased {
			res.Erased++
		}
		wantSeq++
		wantPrev = hash
	}
	if err := rows.Err(); err != nil {
		return res, wrap("verify audit chain", err)
	}
	return res, nil
}

// auditSecretIfPresent reads the secret without creating it (verification is read-only).
func (s *Store) auditSecretIfPresent(ctx context.Context) ([]byte, error) {
	var secret []byte
	err := s.db.QueryRowContext(ctx, s.q(`SELECT secret FROM theauth_audit_secrets WHERE id = 1`)).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return secret, err
}

func isNoSuchColumn(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "no such column") || strings.Contains(err.Error(), "no such table"))
}

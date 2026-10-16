package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/glincker/theauth-go/v2"
	"github.com/oklog/ulid/v2"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 200
)

// InsertAuditEvents appends a batch in one transaction. Rows are linked into a
// per-organization hash chain (see VerifyAuditChain). If the database has not
// run migration 0017 the rows are written without chain or accountability
// columns, so hosts upgrading in two steps keep working.
func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	err := s.inTx(ctx, "insert audit events", func(tx DBTX) error {
		return s.insertChained(ctx, tx, events)
	})
	if isNoSuchColumn(err) {
		return s.inTx(ctx, "insert audit events", func(tx DBTX) error {
			return s.insertLegacy(ctx, tx, events)
		})
	}
	return err
}

func marshalOr(v any, empty string) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(raw) == "null" {
		return empty, nil
	}
	return string(raw), nil
}

type chainHead struct {
	seq  int64
	hash string
}

func (s *Store) insertChained(ctx context.Context, tx DBTX, events []theauth.AuditEvent) error {
	stmt, err := tx.PrepareContext(ctx, s.q(`
INSERT INTO theauth_audit_events
	(id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	 metadata, ip, user_agent, created_at,
	 subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
	 actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
	 chain_key, chain_seq, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	secret, err := s.auditSecret(ctx, tx)
	if err != nil {
		return err
	}
	heads := map[string]chainHead{}
	for _, e := range events {
		meta, err := marshalOr(e.Metadata, "{}")
		if err != nil {
			return fmt.Errorf("marshal audit metadata: %w", err)
		}
		chain, err := marshalOr(e.DelegationChain, "[]")
		if err != nil {
			return fmt.Errorf("marshal delegation chain: %w", err)
		}
		prov, err := marshalOr(e.InputProvenance, "{}")
		if err != nil {
			return fmt.Errorf("marshal input provenance: %w", err)
		}
		keyStr := ""
		if e.OrganizationID != nil {
			keyStr = idStr(*e.OrganizationID)
		}
		head, ok := heads[keyStr]
		if !ok {
			head, err = s.readChainHead(ctx, tx, keyStr)
			if err != nil {
				return err
			}
		}
		p := auditChainPayload{
			ChainKey: keyStr, Seq: head.seq + 1, Prev: head.hash, ID: idStr(e.ID), Org: keyStr,
			Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID, Metadata: meta,
			IP: e.IP, UserAgent: e.UserAgent, CreatedAt: toMicro(orNow(e.CreatedAt)),
			SubjectPseudo: auditPseudonym(secret, e.SubjectID), ActorPseudo: auditPseudonym(secret, e.ActorID),
			PolicyVersion: e.PolicyVersion, ApproverPseudo: auditPseudonym(secret, e.ApproverID),
			DelegationChain: chain, InputProvenance: prov,
		}
		if e.ActorUserID != nil {
			p.ActorUserPseudo = auditPseudonym(secret, idStr(*e.ActorUserID))
		}
		if e.ActorSessionID != nil {
			p.ActorSession = idStr(*e.ActorSessionID)
		}
		hash, err := auditRowHash(p)
		if err != nil {
			return fmt.Errorf("hash audit event: %w", err)
		}
		if _, err := stmt.ExecContext(ctx, p.ID, idPtrStr(e.OrganizationID), idPtrStr(e.ActorUserID),
			idPtrStr(e.ActorSessionID), e.Action, e.TargetType, e.TargetID, meta, e.IP, e.UserAgent,
			p.CreatedAt, e.SubjectID, e.ActorID, e.PolicyVersion, e.ApproverID, chain, prov,
			p.ActorUserPseudo, p.SubjectPseudo, p.ActorPseudo, p.ApproverPseudo,
			keyStr, p.Seq, p.Prev, hash); err != nil {
			return err
		}
		heads[keyStr] = chainHead{seq: p.Seq, hash: hash}
	}
	return nil
}

func (s *Store) readChainHead(ctx context.Context, tx DBTX, key string) (chainHead, error) {
	var h chainHead
	err := tx.QueryRowContext(ctx, s.q(`
SELECT chain_seq, hash FROM theauth_audit_events
WHERE chain_key = ? AND chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`), key).Scan(&h.seq, &h.hash)
	if errors.Is(err, sql.ErrNoRows) {
		return chainHead{}, nil
	}
	return h, err
}

func (s *Store) insertLegacy(ctx context.Context, tx DBTX, events []theauth.AuditEvent) error {
	stmt, err := tx.PrepareContext(ctx, s.q(`
INSERT INTO theauth_audit_events
	(id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	 metadata, ip, user_agent, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, e := range events {
		meta, err := marshalOr(e.MetadataWithAccountability(), "{}")
		if err != nil {
			return fmt.Errorf("marshal audit metadata: %w", err)
		}
		if _, err := stmt.ExecContext(ctx, idStr(e.ID), idPtrStr(e.OrganizationID), idPtrStr(e.ActorUserID),
			idPtrStr(e.ActorSessionID), e.Action, e.TargetType, e.TargetID, meta, e.IP, e.UserAgent,
			toMicro(orNow(e.CreatedAt))); err != nil {
			return err
		}
	}
	return nil
}

// QueryAuditEvents returns events newest first with keyset pagination over (created_at, id).
func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	out, next, err := s.queryAuditEvents(ctx, q, false)
	if isNoSuchColumn(err) {
		return s.queryAuditEvents(ctx, q, true)
	}
	return out, next, err
}

func (s *Store) queryAuditEvents(ctx context.Context, q theauth.AuditQuery, legacy bool) ([]theauth.AuditEvent, string, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = auditDefaultLimit
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}

	var (
		wheres []string
		args   []any
	)
	if q.OrganizationID != nil {
		wheres, args = append(wheres, "organization_id = ?"), append(args, idStr(*q.OrganizationID))
	}
	if q.ActorUserID != nil {
		wheres, args = append(wheres, "actor_user_id = ?"), append(args, idStr(*q.ActorUserID))
	}
	if q.Action != "" {
		wheres, args = append(wheres, "action = ?"), append(args, q.Action)
	}
	if q.TargetType != "" {
		wheres, args = append(wheres, "target_type = ?"), append(args, q.TargetType)
	}
	if q.TargetID != "" {
		wheres, args = append(wheres, "target_id = ?"), append(args, q.TargetID)
	}
	if q.Since != nil {
		wheres, args = append(wheres, "created_at >= ?"), append(args, toMicro(*q.Since))
	}
	if q.Until != nil {
		wheres, args = append(wheres, "created_at <= ?"), append(args, toMicro(*q.Until))
	}
	if q.After != "" {
		micros, id, err := decodeAuditCursor(q.After)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w: %w", theauth.ErrBadCursor, err)
		}
		wheres = append(wheres, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, micros, micros, id)
	}

	// Before migration 0017 the accountability columns do not exist; select
	// constants in their place so scanAudit stays one code path.
	extra := `subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
	COALESCE(chain_seq, 0), prev_hash, hash`
	if legacy {
		extra = `'', '', '', '', '[]', '{}', 0, '', ''`
	}
	query := `SELECT id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	metadata, ip, user_agent, created_at, ` + extra + ` FROM theauth_audit_events`
	if len(wheres) > 0 {
		query += " WHERE " + strings.Join(wheres, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, "", wrap("query audit events", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]theauth.AuditEvent, 0, limit)
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, "", wrap("query audit events", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", wrap("query audit events", err)
	}
	var next string
	if len(out) == limit {
		last := out[len(out)-1]
		next = encodeAuditCursor(toMicro(last.CreatedAt), last.ID.String())
	}
	return out, next, nil
}

func scanAudit(r scanner) (theauth.AuditEvent, error) {
	var (
		id                           string
		org, actor, sess             sql.NullString
		action, ttype, tid, meta, ip string
		ua                           string
		created                      int64
		subject, actorID, policy     string
		approver, chain, prov        string
		seq                          int64
		prev, hash                   string
	)
	if err := r.Scan(&id, &org, &actor, &sess, &action, &ttype, &tid, &meta, &ip, &ua, &created,
		&subject, &actorID, &policy, &approver, &chain, &prov, &seq, &prev, &hash); err != nil {
		return theauth.AuditEvent{}, err
	}
	eid, err := parseID(id)
	if err != nil {
		return theauth.AuditEvent{}, err
	}
	e := theauth.AuditEvent{
		ID: eid, Action: action, TargetType: ttype, TargetID: tid, IP: ip, UserAgent: ua,
		CreatedAt: fromMicro(created),
		SubjectID: subject, ActorID: actorID, PolicyVersion: policy, ApproverID: approver,
		ChainSeq: uint64(seq), PrevHash: prev, Hash: hash,
	}
	if chain != "" && chain != "[]" {
		if err := json.Unmarshal([]byte(chain), &e.DelegationChain); err != nil {
			return theauth.AuditEvent{}, fmt.Errorf("decode delegation chain: %w", err)
		}
	}
	if prov != "" && prov != "{}" {
		if err := json.Unmarshal([]byte(prov), &e.InputProvenance); err != nil {
			return theauth.AuditEvent{}, fmt.Errorf("decode input provenance: %w", err)
		}
	}
	if e.OrganizationID, err = parseIDPtr(org); err != nil {
		return theauth.AuditEvent{}, err
	}
	if e.ActorUserID, err = parseIDPtr(actor); err != nil {
		return theauth.AuditEvent{}, err
	}
	if e.ActorSessionID, err = parseIDPtr(sess); err != nil {
		return theauth.AuditEvent{}, err
	}
	if meta != "" && meta != "{}" {
		if err := json.Unmarshal([]byte(meta), &e.Metadata); err != nil {
			return theauth.AuditEvent{}, fmt.Errorf("decode audit metadata: %w", err)
		}
	}
	return e, nil
}

func encodeAuditCursor(micros int64, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(micros, 10) + ":" + id))
}

func decodeAuditCursor(s string) (int64, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, "", fmt.Errorf("cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("cursor format")
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("cursor timestamp: %w", err)
	}
	if _, err := ulid.Parse(parts[1]); err != nil {
		return 0, "", fmt.Errorf("cursor id: %w", err)
	}
	return micros, parts[1], nil
}

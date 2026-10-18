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
	"github.com/glincker/theauth-go/v2/audit"
	"github.com/oklog/ulid/v2"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 200
)

// InsertAuditEvents appends a batch in one transaction. Rows are linked into a
// per-organization hash chain (see VerifyAuditChain) and stamped with
// recorded_at_us and event (migration 0036). A database that has run 0017 but
// not 0036 gets chained rows without those two columns; one that has not run
// 0017 gets rows without chain or accountability columns, so hosts upgrading in
// steps keep working.
func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	err := s.inTx(ctx, "insert audit events", func(tx DBTX) error {
		return s.insertChained(ctx, tx, events, true)
	})
	if isNoSuchColumn(err) {
		err = s.inTx(ctx, "insert audit events", func(tx DBTX) error {
			return s.insertChained(ctx, tx, events, false)
		})
	}
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
	// recordedAtUs is the stamp of the chain's last row (0 before 0036 or for an empty chain).
	recordedAtUs int64
}

// insertChained writes the batch under one transaction. Within a transaction the head read and the
// inserts are one critical section for the chain: the unique (chain_key, chain_seq) index makes a
// racing writer fail instead of forking the chain. withOrder also writes recorded_at_us and event;
// the stamp is assigned above the chain's last stamp (audit.NextRecordedAtUs), a caller supplied
// RecordedAtUs is ignored, and neither column is hashed.
func (s *Store) insertChained(ctx context.Context, tx DBTX, events []theauth.AuditEvent, withOrder bool) error {
	cols, marks := "", ""
	if withOrder {
		cols, marks = ", recorded_at_us, event", ", ?, ?"
	}
	stmt, err := tx.PrepareContext(ctx, s.q(`
INSERT INTO theauth_audit_events
	(id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	 metadata, ip, user_agent, created_at,
	 subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
	 actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
	 chain_key, chain_seq, prev_hash, hash`+cols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`+marks+`)`))
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
			head, err = s.readChainHead(ctx, tx, keyStr, withOrder)
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
		args := []any{p.ID, idPtrStr(e.OrganizationID), idPtrStr(e.ActorUserID),
			idPtrStr(e.ActorSessionID), e.Action, e.TargetType, e.TargetID, meta, e.IP, e.UserAgent,
			p.CreatedAt, e.SubjectID, e.ActorID, e.PolicyVersion, e.ApproverID, chain, prov,
			p.ActorUserPseudo, p.SubjectPseudo, p.ActorPseudo, p.ApproverPseudo,
			keyStr, p.Seq, p.Prev, hash}
		stamp := head.recordedAtUs
		if withOrder {
			stamp = audit.NextRecordedAtUs(head.recordedAtUs)
			var event any
			if e.Event != "" {
				event = e.Event
			}
			args = append(args, stamp, event)
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
		heads[keyStr] = chainHead{seq: p.Seq, hash: hash, recordedAtUs: stamp}
	}
	return nil
}

func (s *Store) readChainHead(ctx context.Context, tx DBTX, key string, withOrder bool) (chainHead, error) {
	stamp := "0"
	if withOrder {
		stamp = "COALESCE(recorded_at_us, 0)"
	}
	var h chainHead
	err := tx.QueryRowContext(ctx, s.q(`
SELECT chain_seq, hash, `+stamp+` FROM theauth_audit_events
WHERE chain_key = ? AND chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`), key).Scan(&h.seq, &h.hash, &h.recordedAtUs)
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

// AuditOrderSupported declares write order support (storagetest.AuditOrderCapable).
func (s *Store) AuditOrderSupported() bool { return true }

// QueryAuditEvents returns events ordered by (recorded_at_us, id) in q.Order (default desc) and pages
// with a "c1." keyset cursor. A cursor from before write order existed keeps the old
// (created_at DESC, id DESC) keyset, for descending reads only. Before migration 0036 the stamp falls
// back to created_at and the event is NULL; before 0017 the accountability columns are constants.
func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	order, ok := audit.NormalizeOrder(q.Order)
	if !ok {
		return nil, "", theauth.ErrBadAuditOrder
	}
	for _, level := range []auditSchema{auditSchemaOrdered, auditSchemaChained} {
		out, next, err := s.queryAuditEvents(ctx, q, order, level)
		if !isNoSuchColumn(err) {
			return out, next, err
		}
	}
	return s.queryAuditEvents(ctx, q, order, auditSchemaLegacy)
}

// auditSchema is how far the audit table has been migrated.
type auditSchema int

const (
	auditSchemaLegacy  auditSchema = iota // 0005 only
	auditSchemaChained                    // 0017
	auditSchemaOrdered                    // 0036
)

func (s *Store) queryAuditEvents(ctx context.Context, q theauth.AuditQuery, order string, level auditSchema) ([]theauth.AuditEvent, string, error) {
	legacyCursor := audit.IsLegacyCursor(q.After)
	if legacyCursor && order != theauth.AuditOrderDesc {
		return nil, "", fmt.Errorf("%w: legacy cursor needs desc order", theauth.ErrBadCursor)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = auditDefaultLimit
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}
	stampCol, eventCol := "recorded_at_us", "event"
	if level < auditSchemaOrdered {
		stampCol, eventCol = "created_at", "NULL"
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
	if q.Event != "" {
		wheres, args = append(wheres, eventCol+" = ?"), append(args, q.Event)
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
	dir, cmp := "DESC", "<"
	if order == theauth.AuditOrderAsc {
		dir, cmp = "ASC", ">"
	}
	orderBy := " ORDER BY " + stampCol + " " + dir + ", id " + dir
	switch {
	case legacyCursor:
		micros, id, err := decodeAuditCursor(q.After)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w: %w", theauth.ErrBadCursor, err)
		}
		wheres = append(wheres, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, micros, micros, id)
		orderBy = " ORDER BY created_at DESC, id DESC"
	case q.After != "":
		c, err := audit.DecodeCursor(q.After, order)
		if err != nil {
			return nil, "", err
		}
		wheres = append(wheres, "("+stampCol+" "+cmp+" ? OR ("+stampCol+" = ? AND id "+cmp+" ?))")
		args = append(args, c.RecordedAtUs, c.RecordedAtUs, c.ID.String())
	}

	// Before migration 0017 the accountability columns do not exist; select
	// constants in their place so scanAudit stays one code path.
	extra := `subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
	COALESCE(chain_seq, 0), prev_hash, hash`
	if level == auditSchemaLegacy {
		extra = `'', '', '', '', '[]', '{}', 0, '', ''`
	}
	stampSel := "COALESCE(" + stampCol + ", created_at)"
	query := `SELECT id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	metadata, ip, user_agent, created_at, ` + extra + `, ` + stampSel + `, ` + eventCol + ` FROM theauth_audit_events`
	if len(wheres) > 0 {
		query += " WHERE " + strings.Join(wheres, " AND ")
	}
	query += orderBy + " LIMIT ?"
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
		if legacyCursor {
			next = encodeAuditCursor(toMicro(last.CreatedAt), last.ID.String())
		} else {
			next = audit.EncodeCursor(audit.Cursor{RecordedAtUs: last.RecordedAtUs, ID: last.ID, Order: order})
		}
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
		recorded                     int64
		event                        sql.NullString
	)
	if err := r.Scan(&id, &org, &actor, &sess, &action, &ttype, &tid, &meta, &ip, &ua, &created,
		&subject, &actorID, &policy, &approver, &chain, &prov, &seq, &prev, &hash, &recorded, &event); err != nil {
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
		RecordedAtUs: recorded, Event: event.String,
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

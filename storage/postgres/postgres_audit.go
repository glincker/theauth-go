package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/jackc/pgx/v5/pgtype"
)

const insertChainedAuditSQL = `
INSERT INTO audit_events
    (id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
     metadata, ip, user_agent, created_at,
     subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
     actor_user_pseudonym, subject_pseudonym, actor_pseudonym, approver_pseudonym,
     chain_metadata, chain_ip, chain_session, chain_key, chain_seq, prev_hash, hash,
     recorded_at_us, event)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
        $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)`

// InsertAuditEvents appends a batch in one transaction. Rows are linked into a
// per-organization hash chain (see VerifyAuditChain); concurrent writers are
// serialized per chain by a row lock on the chain head (see lockChainHeads).
func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Secret first, then head locks: every writer takes locks in this order.
	secret, err := auditSecret(ctx, tx)
	if err != nil {
		return err
	}
	// Period secrets are taken before the head locks, like the installation secret, so every
	// writer acquires in the same order.
	times := make([]time.Time, len(events))
	for i, e := range events {
		times[i] = e.CreatedAt
		if times[i].IsZero() {
			times[i] = time.Now()
		}
	}
	ps, err := s.rot.Resolve(ctx, secret, pgPeriods{tx}, times)
	if err != nil {
		return err
	}
	heads, stamps, err := lockChainHeads(ctx, tx, events)
	if err != nil {
		return err
	}
	for i, e := range events {
		e.CreatedAt = times[i]
		key := audit.ChainKey(e)
		entry, err := audit.BuildChainEntryWith(e, ps, heads[key])
		if err != nil {
			return err
		}
		var ipText pgtype.Text
		if e.IP != "" {
			if _, perr := netip.ParseAddr(e.IP); perr == nil {
				ipText = pgtype.Text{String: e.IP, Valid: true}
			}
		}
		p := entry.Payload
		// Assigned under the chain head row lock: above the chain's last stamp, so it is strictly
		// increasing per chain. A caller supplied RecordedAtUs is ignored. Not part of the hash.
		stamp := audit.NextRecordedAtUs(stamps[key])
		if _, err := tx.Exec(ctx, insertChainedAuditSQL,
			ulidToPgUUID(e.ID), ulidPtrToPgUUID(e.OrganizationID), ulidPtrToPgUUID(e.ActorUserID),
			ulidPtrToPgUUID(e.ActorSessionID), e.Action, nullableText(e.TargetType), nullableText(e.TargetID),
			[]byte(entry.Metadata), ipText, nullableText(e.UserAgent),
			timeToTs(time.UnixMicro(entry.CreatedAtMicro).UTC()),
			e.SubjectID, e.ActorID, e.PolicyVersion, e.ApproverID, entry.DelegationChain, entry.InputProvenance,
			p.ActorUserPseudo, p.SubjectPseudo, p.ActorPseudo, p.ApproverPseudo,
			entry.Metadata, e.IP, p.ActorSession, key, p.Seq, p.Prev, entry.Hash,
			stamp, nullableText(e.Event)); err != nil {
			return err
		}
		stamps[key] = stamp
		heads[key] = audit.ChainHead{Seq: p.Seq, Hash: entry.Hash}
	}
	for k, h := range heads {
		if _, err := tx.Exec(ctx, `UPDATE theauth_audit_chain_heads SET seq = $2, hash = $3, recorded_at_us = $4 WHERE chain_key = $1`,
			k, h.Seq, h.Hash, stamps[k]); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AuditOrderSupported declares write order support (storagetest.AuditOrderCapable).
func (s *Store) AuditOrderSupported() bool { return true }

// QueryAuditEvents is hand-built because the filter combinations vary too much for a fixed sqlc
// query. Rows are ordered by (recorded_at_us, id) in q.Order (default desc) and paged with a "c1."
// keyset cursor. A cursor from before write order existed keeps the old (created_at DESC, id DESC)
// keyset, for descending reads only.
func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	order, ok := audit.NormalizeOrder(q.Order)
	if !ok {
		return nil, "", theauth.ErrBadAuditOrder
	}
	legacy := audit.IsLegacyCursor(q.After)
	if legacy && order != theauth.AuditOrderDesc {
		return nil, "", fmt.Errorf("%w: legacy cursor needs desc order", theauth.ErrBadCursor)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	var (
		wheres []string
		args   []any
	)
	bind := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if q.OrganizationID != nil {
		wheres = append(wheres, "organization_id = "+bind(ulidToPgUUID(*q.OrganizationID)))
	}
	if q.ActorUserID != nil {
		wheres = append(wheres, "actor_user_id = "+bind(ulidToPgUUID(*q.ActorUserID)))
	}
	if q.Action != "" {
		wheres = append(wheres, "action = "+bind(q.Action))
	}
	if q.Event != "" {
		wheres = append(wheres, "event = "+bind(q.Event))
	}
	if q.TargetType != "" {
		wheres = append(wheres, "target_type = "+bind(q.TargetType))
	}
	if q.TargetID != "" {
		wheres = append(wheres, "target_id = "+bind(q.TargetID))
	}
	if q.Since != nil {
		wheres = append(wheres, "created_at >= "+bind(timeToTs(*q.Since)))
	}
	if q.Until != nil {
		wheres = append(wheres, "created_at <= "+bind(timeToTs(*q.Until)))
	}
	if q.Provenance != nil {
		needle, err := audit.ProvenanceNeedle(*q.Provenance)
		if err != nil {
			return nil, "", err
		}
		if needle != "" {
			// strpos is a literal search. LIKE would treat the underscore in "user_message" as a wildcard.
			wheres = append(wheres, "strpos(input_provenance, "+bind(needle)+") > 0")
		}
	}
	dir, cmp := "DESC", "<"
	if order == theauth.AuditOrderAsc {
		dir, cmp = "ASC", ">"
	}
	orderBy := " ORDER BY recorded_at_us " + dir + ", id " + dir
	switch {
	case legacy:
		ts, id, err := decodeKeysetCursor(q.After)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w: %w", theauth.ErrBadCursor, err)
		}
		// Keyset: (created_at, id) < (cursor_ts, cursor_id) in DESC order.
		wheres = append(wheres,
			"(created_at < "+bind(timeToTs(ts))+
				" OR (created_at = "+bind(timeToTs(ts))+
				" AND id < "+bind(ulidToPgUUID(id))+"))")
		orderBy = " ORDER BY created_at DESC, id DESC"
	case q.After != "":
		c, err := audit.DecodeCursor(q.After, order)
		if err != nil {
			return nil, "", err
		}
		wheres = append(wheres,
			"(recorded_at_us "+cmp+" "+bind(c.RecordedAtUs)+
				" OR (recorded_at_us = "+bind(c.RecordedAtUs)+
				" AND id "+cmp+" "+bind(ulidToPgUUID(c.ID))+"))")
	}
	sql := `SELECT id, organization_id, actor_user_id, actor_session_id,
                   action, target_type, target_id, metadata,
                   host(ip) AS ip, user_agent, created_at,
                   subject_id, actor_id, policy_version, approver_id, delegation_chain, input_provenance,
                   COALESCE(chain_seq, 0), prev_hash, hash, recorded_at_us, event
              FROM audit_events`
	if len(wheres) > 0 {
		sql += " WHERE " + strings.Join(wheres, " AND ")
	}
	sql += orderBy + " LIMIT " + strconv.Itoa(limit)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make([]theauth.AuditEvent, 0, limit)
	for rows.Next() {
		var (
			id, orgID, actorUser, actorSess pgtype.UUID
			action                          string
			targetType, targetID, ipTxt, ua pgtype.Text
			metaBytes                       []byte
			createdAt                       pgtype.Timestamptz
			subject, actorID, policy        string
			approver, chain, prov           string
			seq                             int64
			prev, hash                      string
			recordedUs                      pgtype.Int8
			event                           pgtype.Text
		)
		if err := rows.Scan(&id, &orgID, &actorUser, &actorSess,
			&action, &targetType, &targetID, &metaBytes,
			&ipTxt, &ua, &createdAt,
			&subject, &actorID, &policy, &approver, &chain, &prov, &seq, &prev, &hash, &recordedUs, &event); err != nil {
			return nil, "", err
		}
		e := theauth.AuditEvent{
			ID:             pgUUIDToULID(id),
			OrganizationID: pgUUIDToULIDPtr(orgID),
			ActorUserID:    pgUUIDToULIDPtr(actorUser),
			ActorSessionID: pgUUIDToULIDPtr(actorSess),
			Action:         action,
			TargetType:     pgTextString(targetType),
			TargetID:       pgTextString(targetID),
			IP:             pgTextString(ipTxt),
			UserAgent:      pgTextString(ua),
			CreatedAt:      tsToTime(createdAt),
			SubjectID:      subject, ActorID: actorID, PolicyVersion: policy, ApproverID: approver,
			ChainSeq: uint64(seq), PrevHash: prev, Hash: hash,
			RecordedAtUs: recordedUs.Int64, Event: pgTextString(event),
		}
		if chain != "" && chain != "[]" {
			if err := json.Unmarshal([]byte(chain), &e.DelegationChain); err != nil {
				return nil, "", fmt.Errorf("decode delegation chain: %w", err)
			}
		}
		if prov != "" && prov != "{}" {
			if err := json.Unmarshal([]byte(prov), &e.InputProvenance); err != nil {
				return nil, "", fmt.Errorf("decode input provenance: %w", err)
			}
		}
		if len(metaBytes) > 0 {
			var meta map[string]any
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				e.Metadata = meta
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var next string
	if len(out) == limit {
		last := out[len(out)-1]
		if legacy {
			next = encodeKeysetCursor(last.CreatedAt, last.ID)
		} else {
			next = audit.EncodeCursor(audit.Cursor{RecordedAtUs: last.RecordedAtUs, ID: last.ID, Order: order})
		}
	}
	return out, next, nil
}

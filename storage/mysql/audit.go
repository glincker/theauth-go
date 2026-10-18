package mysql

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/oklog/ulid/v2"
)

// Audit events. InsertAuditEvents lives in audit_chain.go with the hash chain.

// AuditOrderSupported declares write order support (storagetest.AuditOrderCapable): the store
// assigns recorded_at_us, persists event, and serves Order, the Event filter and c1. cursors.
func (s *Store) AuditOrderSupported() bool { return true }

func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	order, ok := audit.NormalizeOrder(q.Order)
	if !ok {
		return nil, "", theauth.ErrBadAuditOrder
	}
	legacy := audit.IsLegacyCursor(q.After)
	if legacy && order != theauth.AuditOrderDesc {
		return nil, "", fmt.Errorf("pagination.bad_cursor: %w: legacy cursor needs desc order", theauth.ErrBadCursor)
	}

	var wheres []string
	var args []interface{}

	if q.OrganizationID != nil {
		wheres = append(wheres, "organization_id = ?")
		args = append(args, ulidToBytes(*q.OrganizationID))
	}
	if q.ActorUserID != nil {
		wheres = append(wheres, "actor_user_id = ?")
		args = append(args, ulidToBytes(*q.ActorUserID))
	}
	if q.Action != "" {
		wheres = append(wheres, "action = ?")
		args = append(args, q.Action)
	}
	if q.TargetType != "" {
		wheres = append(wheres, "target_type = ?")
		args = append(args, q.TargetType)
	}
	if q.TargetID != "" {
		wheres = append(wheres, "target_id = ?")
		args = append(args, q.TargetID)
	}
	if q.Event != "" {
		wheres = append(wheres, "event = ?")
		args = append(args, q.Event)
	}
	if q.Since != nil {
		wheres = append(wheres, "created_at >= ?")
		args = append(args, timeUTC(*q.Since))
	}
	if q.Until != nil {
		wheres = append(wheres, "created_at <= ?")
		args = append(args, timeUTC(*q.Until))
	}
	switch {
	case legacy:
		ts, id, err := decodeAuditCursor(q.After)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w: %w", theauth.ErrBadCursor, err)
		}
		// Legacy keyset: (created_at, id) < (cursor_ts, cursor_id) in DESC order.
		wheres = append(wheres,
			"(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, timeUTC(ts), timeUTC(ts), ulidToBytes(id))
	case q.After != "":
		c, err := audit.DecodeCursor(q.After, order)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w", err)
		}
		// Write order keyset on (recorded_at_us, id), strictly after the cursor row in the
		// requested direction.
		cmp := "<"
		if order == theauth.AuditOrderAsc {
			cmp = ">"
		}
		wheres = append(wheres,
			"(recorded_at_us "+cmp+" ? OR (recorded_at_us = ? AND id "+cmp+" ?))")
		args = append(args, c.RecordedAtUs, c.RecordedAtUs, ulidToBytes(c.ID))
	}

	sqlStr := `SELECT id, organization_id, actor_user_id, actor_session_id,
                      action, target_type, target_id, metadata, ip, user_agent, created_at,
                      subject_id, actor_id, policy_version, approver_id,
                      COALESCE(delegation_chain, '[]'), COALESCE(input_provenance, '{}'),
                      COALESCE(chain_seq, 0), prev_hash, hash,
                      event, COALESCE(recorded_at_us, 0)
               FROM audit_events`
	if len(wheres) > 0 {
		sqlStr += " WHERE " + strings.Join(wheres, " AND ")
	}
	switch {
	case legacy:
		sqlStr += " ORDER BY created_at DESC, id DESC"
	case order == theauth.AuditOrderAsc:
		sqlStr += " ORDER BY recorded_at_us ASC, id ASC"
	default:
		sqlStr += " ORDER BY recorded_at_us DESC, id DESC"
	}
	sqlStr += " LIMIT " + strconv.Itoa(limit)

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	out := make([]theauth.AuditEvent, 0, limit)
	for rows.Next() {
		var (
			idB, orgIDB, actorUserB, actorSessB []byte
			action                              string
			targetType, targetID                nullableStr
			metaBytes                           []byte
			ip, ua                              nullableStr
			createdAt                           time.Time
			subject, actorID, policy, approver  string
			chain, prov                         string
			seq                                 int64
			prev, hash                          string
			event                               nullableStr
			recordedUs                          int64
		)
		if err := rows.Scan(
			&idB, &orgIDB, &actorUserB, &actorSessB,
			&action, &targetType, &targetID, &metaBytes, &ip, &ua, &createdAt,
			&subject, &actorID, &policy, &approver, &chain, &prov, &seq, &prev, &hash, &event, &recordedUs,
		); err != nil {
			return nil, "", err
		}
		e := theauth.AuditEvent{
			ID:             bytesToULID(idB),
			OrganizationID: bytesToULIDPtr(orgIDB),
			ActorUserID:    bytesToULIDPtr(actorUserB),
			ActorSessionID: bytesToULIDPtr(actorSessB),
			Action:         action,
			TargetType:     targetType.value(),
			TargetID:       targetID.value(),
			IP:             ip.value(),
			UserAgent:      ua.value(),
			CreatedAt:      createdAt.UTC(),
			SubjectID:      subject, ActorID: actorID, PolicyVersion: policy, ApproverID: approver,
			ChainSeq: uint64(seq), PrevHash: prev, Hash: hash,
			Event: event.value(), RecordedAtUs: recordedUs,
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
			var meta map[string]interface{}
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				e.Metadata = meta
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var nextCursor string
	if len(out) == limit {
		last := out[len(out)-1]
		if legacy {
			nextCursor = encodeAuditCursor(last.CreatedAt, last.ID)
		} else {
			nextCursor = audit.EncodeCursor(audit.Cursor{RecordedAtUs: last.RecordedAtUs, ID: last.ID, Order: order})
		}
	}
	return out, nextCursor, nil
}

// nullableStr helps scan nullable VARCHAR/TEXT columns.
type nullableStr struct {
	valid bool
	s     string
}

func (n *nullableStr) Scan(src interface{}) error {
	if src == nil {
		n.valid = false
		return nil
	}
	switch v := src.(type) {
	case string:
		n.s = v
		n.valid = true
	case []byte:
		n.s = string(v)
		n.valid = true
	}
	return nil
}

func (n nullableStr) value() string {
	if !n.valid {
		return ""
	}
	return n.s
}

func encodeAuditCursor(ts time.Time, id theauth.ULID) string {
	raw := strconv.FormatInt(ts.UnixMicro(), 10) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeAuditCursor(s string) (time.Time, theauth.ULID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor format")
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor micros: %w", err)
	}
	id, err := ulid.Parse(parts[1])
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor ulid: %w", err)
	}
	return time.UnixMicro(micros), id, nil
}

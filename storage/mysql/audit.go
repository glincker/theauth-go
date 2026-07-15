package mysql

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/oklog/ulid/v2"
)

// ---------- Audit events ----------

func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range events {
		metaBytes, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit metadata marshal: %w", err)
		}
		if string(metaBytes) == "null" {
			metaBytes = []byte("{}")
		}
		var ipVal interface{}
		if e.IP != "" {
			ipVal = e.IP
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events
    (id, organization_id, actor_user_id, actor_session_id,
     action, target_type, target_id, metadata, ip, user_agent, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ulidToBytes(e.ID),
			ulidPtrToBytes(e.OrganizationID),
			ulidPtrToBytes(e.ActorUserID),
			ulidPtrToBytes(e.ActorSessionID),
			e.Action,
			nullStringVal(e.TargetType),
			nullStringVal(e.TargetID),
			metaBytes,
			ipVal,
			nullStringVal(e.UserAgent),
			timeUTC(e.CreatedAt),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
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
	if q.Since != nil {
		wheres = append(wheres, "created_at >= ?")
		args = append(args, timeUTC(*q.Since))
	}
	if q.Until != nil {
		wheres = append(wheres, "created_at <= ?")
		args = append(args, timeUTC(*q.Until))
	}
	if q.After != "" {
		ts, id, err := decodeAuditCursor(q.After)
		if err != nil {
			return nil, "", fmt.Errorf("pagination.bad_cursor: %w: %w", theauth.ErrBadCursor, err)
		}
		// Keyset: (created_at, id) < (cursor_ts, cursor_id) in DESC order.
		wheres = append(wheres,
			"(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, timeUTC(ts), timeUTC(ts), ulidToBytes(id))
	}

	sqlStr := `SELECT id, organization_id, actor_user_id, actor_session_id,
                      action, target_type, target_id, metadata, ip, user_agent, created_at
               FROM audit_events`
	if len(wheres) > 0 {
		sqlStr += " WHERE " + strings.Join(wheres, " AND ")
	}
	sqlStr += " ORDER BY created_at DESC, id DESC LIMIT " + strconv.Itoa(limit)

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
		)
		if err := rows.Scan(
			&idB, &orgIDB, &actorUserB, &actorSessB,
			&action, &targetType, &targetID, &metaBytes, &ip, &ua, &createdAt,
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
		nextCursor = encodeAuditCursor(last.CreatedAt, last.ID)
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

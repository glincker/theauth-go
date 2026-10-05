package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

// InsertAuditEvents appends a batch of events in one transaction.
func (s *Store) InsertAuditEvents(ctx context.Context, events []theauth.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	return s.inTx(ctx, "insert audit events", func(tx *sql.Tx) error {
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
			meta, err := json.Marshal(e.Metadata)
			if err != nil {
				return fmt.Errorf("marshal audit metadata: %w", err)
			}
			if string(meta) == "null" {
				meta = []byte("{}")
			}
			if _, err := stmt.ExecContext(ctx, idStr(e.ID), idPtrStr(e.OrganizationID), idPtrStr(e.ActorUserID),
				idPtrStr(e.ActorSessionID), e.Action, e.TargetType, e.TargetID, string(meta), e.IP, e.UserAgent,
				toMicro(orNow(e.CreatedAt))); err != nil {
				return err
			}
		}
		return nil
	})
}

// QueryAuditEvents returns events newest first with keyset pagination over (created_at, id).
func (s *Store) QueryAuditEvents(ctx context.Context, q theauth.AuditQuery) ([]theauth.AuditEvent, string, error) {
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

	query := `SELECT id, organization_id, actor_user_id, actor_session_id, action, target_type, target_id,
	metadata, ip, user_agent, created_at FROM theauth_audit_events`
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
	)
	if err := r.Scan(&id, &org, &actor, &sess, &action, &ttype, &tid, &meta, &ip, &ua, &created); err != nil {
		return theauth.AuditEvent{}, err
	}
	eid, err := parseID(id)
	if err != nil {
		return theauth.AuditEvent{}, err
	}
	e := theauth.AuditEvent{
		ID: eid, Action: action, TargetType: ttype, TargetID: tid, IP: ip, UserAgent: ua,
		CreatedAt: fromMicro(created),
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

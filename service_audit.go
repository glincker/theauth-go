package theauth

import (
	"context"
	"log/slog"
	"time"
)

// EmitAudit enqueues an audit event for asynchronous batched write. Non-
// blocking: when the writer channel is full the event is dropped and
// Stats.AuditDropped increments by 1. The actor user / session id and the
// request IP / user agent are pulled from ctx when present (Authn populates
// them); callers may also pass a context with those values explicitly
// attached via WithAuditMetadata.
//
// EmitAudit may be called from any goroutine. The metadata map is mutated
// in place by the redactor; callers must not retain references after the
// call (or, equivalently, must defensively copy before passing in).
//
// When Config.Audit is nil EmitAudit is a silent no-op. When Close has been
// called EmitAudit is also a silent no-op (the writer goroutine has drained
// and the channel is closed; pushing would panic).
func (a *TheAuth) EmitAudit(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	if a.auditCfg == nil || !a.auditStarted.Load() || a.auditClosed.Load() {
		return
	}
	if action == "" {
		return
	}
	a.auditEmitted.Add(1)
	evt := AuditEvent{
		ID:         newULID(),
		Action:     action,
		TargetType: target.Type,
		TargetID:   target.ID,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}
	// Apply redactor at emit time. The custom redactor (if any) sees the
	// raw metadata first; the default redactor is applied unconditionally
	// afterwards so a custom redactor cannot accidentally re-introduce
	// secret-flavored keys.
	if a.auditCfg.Redactor != nil {
		evt.Metadata = a.auditCfg.Redactor(evt.Metadata)
	}
	evt.Metadata = DefaultRedactor(evt.Metadata)

	// Hydrate actor + session + IP/UA from ctx synchronously. The writer
	// goroutine never reads ctx (which may have been canceled by the time
	// the batch flushes), so we copy values now.
	if u, ok := UserFromContext(ctx); ok && u != nil {
		id := u.ID
		evt.ActorUserID = &id
	}
	if s, ok := SessionFromContext(ctx); ok && s != nil {
		sid := s.ID
		evt.ActorSessionID = &sid
		if s.ActiveOrganizationID != nil {
			oid := *s.ActiveOrganizationID
			evt.OrganizationID = &oid
		}
	}
	if md, ok := auditMetadataFromContext(ctx); ok {
		if md.OrganizationID != nil {
			oid := *md.OrganizationID
			evt.OrganizationID = &oid
		}
		if md.IP != "" {
			evt.IP = md.IP
		}
		if md.UserAgent != "" {
			evt.UserAgent = md.UserAgent
		}
		if md.ActorUserID != nil {
			id := *md.ActorUserID
			evt.ActorUserID = &id
		}
	}

	select {
	case a.auditCh <- evt:
	default:
		a.auditDropped.Add(1)
	}
}

// QueryAudit returns up to q.Limit events plus an opaque cursor for the
// next page. Caller is responsible for permission-checking; this method
// does no auth.
func (a *TheAuth) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, string, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	return a.storage.QueryAuditEvents(ctx, q)
}

// auditWriterLoop is the single goroutine that drains a.auditCh, batches up
// to BatchSize events or FlushInterval, and issues one INSERT per batch.
// Failures are logged and counted in Stats.AuditFailed without retry per
// the v1.0 design tradeoff.
func (a *TheAuth) auditWriterLoop() {
	defer close(a.auditDone)
	batchSize := a.auditCfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	interval := a.auditCfg.FlushInterval
	if interval <= 0 {
		interval = 1 * time.Second
	}
	buf := make([]AuditEvent, 0, batchSize)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		// Detach from the request context; the writer owns a background
		// ctx so callers' cancellations cannot abort a batch in flight.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := a.storage.InsertAuditEvents(ctx, buf)
		cancel()
		if err != nil {
			a.auditFailed.Add(uint64(len(buf)))
			slog.Error("theauth: audit insert failed", "count", len(buf), "err", err.Error())
		} else {
			a.auditWritten.Add(uint64(len(buf)))
		}
		buf = buf[:0]
	}

	for {
		select {
		case <-a.auditStop:
			// Drain any pending events from the channel without blocking,
			// then flush the buffer and return.
			for {
				select {
				case evt := <-a.auditCh:
					buf = append(buf, evt)
					if len(buf) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case evt := <-a.auditCh:
			buf = append(buf, evt)
			if len(buf) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// AuditMetadata is the optional bundle a caller may attach to a context to
// override the auto-derived actor / org / IP / UA. Useful in tests and in
// background jobs that do not pass through the HTTP middleware.
type AuditMetadata struct {
	OrganizationID *ULID
	ActorUserID    *ULID
	IP             string
	UserAgent      string
}

type ctxKeyAuditMetadataT struct{}

var ctxKeyAuditMetadata ctxKeyAuditMetadataT

// WithAuditMetadata attaches an AuditMetadata to ctx; EmitAudit reads it.
// Overrides values derived from UserFromContext / SessionFromContext when
// the corresponding field is non-zero.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return context.WithValue(ctx, ctxKeyAuditMetadata, md)
}

func auditMetadataFromContext(ctx context.Context) (AuditMetadata, bool) {
	md, ok := ctx.Value(ctxKeyAuditMetadata).(AuditMetadata)
	return md, ok
}

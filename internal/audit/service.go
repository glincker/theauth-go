// Package audit's Service is the goroutine-backed implementation of
// Emitter. PR D architecture reorg (2026-06-20) moved the buffered-channel
// writer + drop-on-backpressure + single-drain-goroutine implementation out
// of root service_audit.go into this package, alongside the existing
// emitter.go Emitter interface.
//
// The Service satisfies Emitter, so internal service packages (rbac,
// magiclink, agent, delegation, AS) continue to take a plain audit.Emitter
// and never see the concrete *Service. The root *theauth.TheAuth holds a
// *Service pointer and exposes EmitAudit / QueryAudit / Stats as thin
// forwarders.
//
// Concurrency contract preserved verbatim from the v1.0 root implementation:
//
//   - EmitAudit is non-blocking. When the channel buffer is full the event
//     is dropped and Dropped increments by 1.
//   - One writer goroutine drains the channel, batches up to BatchSize
//     events (or whichever flush comes first per FlushInterval), and issues
//     one InsertAuditEvents call per batch.
//   - Failures are logged at slog.Error and counted as Failed without
//     retry per the v1.0 design tradeoff.
//   - Stop() closes the stop channel and waits up to DrainTimeout for the
//     writer to drain remaining events. Idempotent.
//   - Race tests must pass -race -count=3.
package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset the audit writer needs.
// Declared here (not imported from root) so internal/audit does not import
// the root theauth package and the constructor cycle stays broken. Any
// type satisfying these two methods (notably the root theauth.Storage
// interface) is a valid argument to NewService.
type Storage interface {
	InsertAuditEvents(ctx context.Context, events []models.AuditEvent) error
	QueryAuditEvents(ctx context.Context, q models.AuditQuery) (events []models.AuditEvent, nextCursor string, err error)
}

// Redactor optionally transforms metadata before storage. See
// DefaultRedactor in the root package for the seeded blocklist; a custom
// redactor receives the raw metadata first and is followed unconditionally
// by the default redactor so a custom redactor cannot re-introduce
// secret-flavored keys.
type Redactor func(metadata map[string]any) map[string]any

// Sink mirrors the root AuditSink interface. Declared here so
// internal/audit can accept sinks without importing the root package
// (which would recreate the constructor cycle). The root AuditSink and
// internal Sink have identical method sets; the root wiring converts
// []theauth.AuditSink into []Sink via a type assertion that always
// succeeds because theauth.AuditSink is a strict superset.
type Sink interface {
	Stream(ctx context.Context, batch []models.AuditEvent) error
	Name() string
}

// Config bundles the runtime knobs for the writer. All fields have safe
// defaults; the zero value Config{} is valid.
type Config struct {
	// BufferSize is the channel buffer between Emit and the writer
	// goroutine. Defaults to 4096. When full, Emit drops the event.
	BufferSize int

	// BatchSize is the maximum events per InsertAuditEvents call.
	// Defaults to 100.
	BatchSize int

	// FlushInterval is the maximum delay before a partial batch flushes.
	// Defaults to 1 second.
	FlushInterval time.Duration

	// CustomRedactor runs before DefaultRedactor at emit time. May be nil.
	CustomRedactor Redactor

	// DefaultRedactor is unconditionally applied after CustomRedactor.
	// The root package's DefaultRedactor is wired here at construction
	// time so this package does not duplicate the seeded blocklist.
	DefaultRedactor Redactor

	// DrainTimeout caps how long Stop waits for the writer goroutine to
	// drain remaining events. Defaults to 5 seconds.
	DrainTimeout time.Duration

	// Sinks is the list of external streaming sinks. After each successful
	// InsertAuditEvents call the writer fans out to each sink in a
	// separate goroutine. Failures are logged and counted in sinkFailed;
	// they never block the canonical storage write or the next batch.
	Sinks []Sink
}

// AuditMetadata is the optional bundle a caller may attach to a context to
// override the auto-derived actor / org / IP / UA. Useful in tests and in
// background jobs that do not pass through the HTTP middleware. Re-exported
// from the root package via a type alias so the public surface is unchanged.
type AuditMetadata struct {
	OrganizationID *models.ULID
	ActorUserID    *models.ULID
	IP             string
	UserAgent      string
}

type ctxKeyAuditMetadataT struct{}

var ctxKeyAuditMetadata ctxKeyAuditMetadataT

// WithAuditMetadata attaches an AuditMetadata to ctx; Service.Emit reads it.
// Overrides values derived from the supplied actor / session when the
// corresponding field is non-zero.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return context.WithValue(ctx, ctxKeyAuditMetadata, md)
}

// MetadataFromContext returns the AuditMetadata attached via
// WithAuditMetadata, if any.
func MetadataFromContext(ctx context.Context) (AuditMetadata, bool) {
	md, ok := ctx.Value(ctxKeyAuditMetadata).(AuditMetadata)
	return md, ok
}

// Service is the goroutine-backed Emitter. Construct one in theauth.New;
// call Start to spawn the writer goroutine; call Stop to drain on shutdown.
//
// Service satisfies Emitter so internal packages can take a plain
// audit.Emitter without depending on the concrete type.
type Service struct {
	storage Storage
	cfg     Config

	// ch carries enqueued events to the writer goroutine. Buffered to
	// BufferSize; Emit drops on overflow.
	ch chan models.AuditEvent
	// stop is closed by Stop to signal the writer goroutine to drain and
	// exit. nil before Start; protected from double-close via started.
	stop chan struct{}
	// done is closed by the writer goroutine when it has drained and is
	// about to return.
	done chan struct{}

	// started + closed prevent racing Start/Stop calls and prevent Emit
	// from pushing onto a closed channel.
	started atomic.Bool
	closed  atomic.Bool

	// Counters mirror the v1.0 root Stats fields. Snapshotted via the
	// Counters method; the root Stats() forwarder reads them.
	emitted    atomic.Uint64
	written    atomic.Uint64
	dropped    atomic.Uint64
	failed     atomic.Uint64
	sinkFailed atomic.Uint64

	// hooks routes audit drops + queue depth into the consumer-supplied
	// metrics adapter. Installed via SetHooks; defaults to a no-op bundle
	// so the service is usable without observability wiring.
	hooks         *obs.Hooks
	mDroppedTotal obs.Counter
	mQueueDepth   obs.Gauge
}

// NewService constructs a Service. cfg may be the zero value; Start applies
// defaults. The Service is not yet running until Start returns.
func NewService(storage Storage, cfg Config) *Service {
	s := &Service{storage: storage, cfg: cfg, hooks: &obs.Hooks{}}
	s.mDroppedTotal = s.hooks.Counter(obs.MetricAuditDroppedTotal, nil)
	s.mQueueDepth = s.hooks.Gauge(obs.MetricAuditQueueDepth, nil)
	return s
}

// SetHooks installs the consumer-supplied observability bundle. MUST be
// called before Start so the metrics instruments are bound to the live
// adapter (not the no-op default the constructor wires). Calling after
// Start is allowed and rebinds the instruments; per-instrument adapters
// like Prometheus that cache by (name, label set) will return the same
// underlying child instrument on the second bind.
func (s *Service) SetHooks(h *obs.Hooks) {
	if s == nil {
		return
	}
	if h == nil {
		h = &obs.Hooks{}
	}
	s.hooks = h
	s.mDroppedTotal = s.hooks.Counter(obs.MetricAuditDroppedTotal, nil)
	s.mQueueDepth = s.hooks.Gauge(obs.MetricAuditQueueDepth, nil)
}

// Start spawns the writer goroutine. Idempotent: a second call is a no-op
// and returns nil. Safe to call after Stop has fully drained.
func (s *Service) Start() error {
	if !s.started.CompareAndSwap(false, true) {
		return nil
	}
	bufSize := s.cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 4096
	}
	s.ch = make(chan models.AuditEvent, bufSize)
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.writerLoop()
	return nil
}

// Stop closes the stop channel and waits up to DrainTimeout for the writer
// goroutine to drain remaining events. Idempotent: a second call is a
// no-op. Safe to call before Start (treated as a no-op).
func (s *Service) Stop() {
	if !s.started.Load() {
		return
	}
	if s.closed.Swap(true) {
		return
	}
	if s.stop != nil {
		select {
		case <-s.stop:
			// already closed
		default:
			close(s.stop)
		}
	}
	timeout := s.cfg.DrainTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if s.done != nil {
		select {
		case <-s.done:
		case <-time.After(timeout):
		}
	}
}

// EmitAudit satisfies the Emitter interface. Equivalent to Emit with a
// nil actor / session / org / ip / ua override; Emit pulls those from
// MetadataFromContext when present.
func (s *Service) EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any) {
	s.Emit(ctx, action, target, metadata, nil, nil)
}

// Emit enqueues an audit event for asynchronous batched write. Non-
// blocking: when the writer channel is full the event is dropped and
// Dropped increments by 1.
//
// actorUser and actorSession let the caller (the root EmitAudit forwarder)
// attach values pulled from the request context. The MetadataFromContext
// helper overrides them when present.
//
// EmitAudit may be called from any goroutine. The metadata map is mutated
// in place by the redactors; callers must not retain references after the
// call (or, equivalently, must defensively copy before passing in).
//
// When the Service is not Started, or has been Stopped, Emit is a silent
// no-op (the writer goroutine has drained and the channel is closed;
// pushing would panic).
func (s *Service) Emit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any, actorUser *models.ULID, actorSession *models.Session) {
	if !s.started.Load() || s.closed.Load() {
		return
	}
	if action == "" {
		return
	}
	s.emitted.Add(1)
	evt := models.AuditEvent{
		ID:         ulid.New(),
		Action:     action,
		TargetType: target.Type,
		TargetID:   target.ID,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}
	// Apply redactors at emit time. The custom redactor (if any) sees the
	// raw metadata first; the default redactor is applied unconditionally
	// afterwards so a custom redactor cannot accidentally re-introduce
	// secret-flavored keys.
	if s.cfg.CustomRedactor != nil {
		evt.Metadata = s.cfg.CustomRedactor(evt.Metadata)
	}
	if s.cfg.DefaultRedactor != nil {
		evt.Metadata = s.cfg.DefaultRedactor(evt.Metadata)
	}

	// Hydrate actor + session + org from the supplied root-side lookup.
	if actorUser != nil {
		id := *actorUser
		evt.ActorUserID = &id
	}
	if actorSession != nil {
		sid := actorSession.ID
		evt.ActorSessionID = &sid
		if actorSession.ActiveOrganizationID != nil {
			oid := *actorSession.ActiveOrganizationID
			evt.OrganizationID = &oid
		}
	}
	// MetadataFromContext overrides anything supplied above (root callers
	// rely on this for SCIM, SAML, and password flows that attach a custom
	// actor / org / ip / ua bundle to ctx).
	if md, ok := MetadataFromContext(ctx); ok {
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
	case s.ch <- evt:
		if s.mQueueDepth != nil {
			s.mQueueDepth.Set(float64(len(s.ch)))
		}
	default:
		s.dropped.Add(1)
		if s.mDroppedTotal != nil {
			s.mDroppedTotal.Inc()
		}
	}
}

// Query returns up to q.Limit events plus an opaque cursor for the next
// page. Caller is responsible for permission-checking; this method does no
// auth.
func (s *Service) Query(ctx context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	return s.storage.QueryAuditEvents(ctx, q)
}

// Counters snapshots the four runtime counters. The root Stats() forwarder
// projects this into the public Stats struct.
type Counters struct {
	Emitted    uint64
	Written    uint64
	Dropped    uint64
	Failed     uint64
	SinkFailed uint64
}

// Counters returns the latest counter snapshot.
func (s *Service) Counters() Counters {
	return Counters{
		Emitted:    s.emitted.Load(),
		Written:    s.written.Load(),
		Dropped:    s.dropped.Load(),
		Failed:     s.failed.Load(),
		SinkFailed: s.sinkFailed.Load(),
	}
}

// writerLoop is the single goroutine that drains s.ch, batches up to
// BatchSize events or FlushInterval, and issues one InsertAuditEvents per
// batch. Failures are logged and counted in Failed without retry.
func (s *Service) writerLoop() {
	defer close(s.done)
	batchSize := s.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	interval := s.cfg.FlushInterval
	if interval <= 0 {
		interval = 1 * time.Second
	}
	buf := make([]models.AuditEvent, 0, batchSize)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		// Detach from the request context; the writer owns a background
		// ctx so callers' cancellations cannot abort a batch in flight.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.storage.InsertAuditEvents(ctx, buf)
		cancel()
		if err != nil {
			s.failed.Add(uint64(len(buf)))
			slog.Error("theauth: audit insert failed", "count", len(buf), "err", err.Error())
		} else {
			s.written.Add(uint64(len(buf)))
			// Fan out to each registered sink. Each sink runs in its own
			// goroutine so a slow or failing sink never delays the writer
			// loop. Failures are best-effort: logged, counted, discarded.
			if len(s.cfg.Sinks) > 0 {
				snapshot := make([]models.AuditEvent, len(buf))
				copy(snapshot, buf)
				for _, sink := range s.cfg.Sinks {
					sink := sink // capture per-iteration
					go func() {
						sinkCtx, sinkCancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer sinkCancel()
						if serr := sink.Stream(sinkCtx, snapshot); serr != nil {
							s.sinkFailed.Add(1)
							slog.Warn("theauth: audit sink failed",
								"sink", sink.Name(),
								"count", len(snapshot),
								"err", serr.Error(),
							)
						}
					}()
				}
			}
		}
		buf = buf[:0]
	}

	for {
		select {
		case <-s.stop:
			// Drain any pending events from the channel without blocking,
			// then flush the buffer and return.
			for {
				select {
				case evt := <-s.ch:
					buf = append(buf, evt)
					if len(buf) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case evt := <-s.ch:
			buf = append(buf, evt)
			if len(buf) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

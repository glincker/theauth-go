// Package audit's Service is the goroutine-backed Emitter. Emit never blocks: a full channel drops
// the event. A single writer batches events, failed writes are counted without retry, and Stop
// drains within DrainTimeout. Race tests must pass with -race -count=3.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// flushTimeout bounds one InsertAuditEvents call, and sinkQueueSize bounds the batches queued per
// sink. Variables so tests can shrink them.
var (
	flushTimeout  = 30 * time.Second
	sinkQueueSize = 16
)

// Storage is the minimal persistence subset the writer needs. It is declared here to keep the
// constructor cycle broken.
type Storage interface {
	InsertAuditEvents(ctx context.Context, events []models.AuditEvent) error
	QueryAuditEvents(ctx context.Context, q models.AuditQuery) (events []models.AuditEvent, nextCursor string, err error)
}

// Redactor transforms metadata before storage. The default redactor always runs after a custom one,
// so a custom redactor cannot reintroduce secret keys.
type Redactor func(metadata map[string]any) map[string]any

// Sink mirrors the root AuditSink interface, which has the same method set, so sinks cross the
// package boundary without an import.
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

	// DefaultRedactor is applied unconditionally after CustomRedactor. The root wires it in, so this
	// package does not duplicate the blocklist.
	DefaultRedactor Redactor

	// DrainTimeout caps how long Stop waits for the writer goroutine to
	// drain remaining events. Defaults to 5 seconds.
	DrainTimeout time.Duration

	// Sinks are external streaming sinks. After each successful write, the writer fans out to every
	// sink in its own goroutine. Sink failures are counted and never block the canonical write.
	Sinks []Sink

	// FailClosed makes EmitDecision return ErrAuditUnavailable when a decision event cannot be queued.
	// Off by default, so audit pressure never fails request paths unless a deployment opts in.
	FailClosed bool

	// DecisionActionPrefixes lists the action prefixes treated as
	// decision-class for FailClosed. Defaults to DefaultDecisionPrefixes.
	DecisionActionPrefixes []string
}

// DefaultDecisionPrefixes are the action prefixes treated as decision-class events when
// Config.DecisionActionPrefixes is empty.
var DefaultDecisionPrefixes = []string{"policy.", "authz.", "approval.", "delegation.", "agent.authorize"}

// ErrAuditUnavailable is returned by EmitDecision, in fail-closed mode, when a
// decision-class event could not be queued.
var ErrAuditUnavailable = errors.New("theauth: audit event could not be recorded")

// GapMarkerAction is the action of the synthetic event written after events
// were dropped. Its metadata carries the dropped count and time window.
const GapMarkerAction = "audit.events_dropped"

// MetricAuditGapMarkersTotal counts gap markers written to storage.
const MetricAuditGapMarkersTotal = "theauth_audit_gap_markers_total"

// AuditMetadata is an optional bundle attached to a context to override the actor, org, IP and UA.
// Background jobs use it.
type AuditMetadata struct {
	OrganizationID *models.ULID
	ActorUserID    *models.ULID
	IP             string
	UserAgent      string

	// Accountability fields copied onto the event when non-empty.
	SubjectID       string
	ActorID         string
	PolicyVersion   string
	ApproverID      string
	DelegationChain []string
	InputProvenance map[string]any

	// Event overrides the event derived from the action (EventForAction) when it is a name in the
	// closed vocabulary. An unknown name is ignored, not stored, so a typo cannot create a value no
	// filter finds; tests catch it through ValidateEvent.
	Event string
}

type ctxKeyAuditMetadataT struct{}

var ctxKeyAuditMetadata ctxKeyAuditMetadataT

// WithAuditMetadata attaches an AuditMetadata to ctx. Non-zero fields override the values derived
// from the request.
func WithAuditMetadata(ctx context.Context, md AuditMetadata) context.Context {
	return context.WithValue(ctx, ctxKeyAuditMetadata, md)
}

// MetadataFromContext returns the AuditMetadata attached via
// WithAuditMetadata, if any.
func MetadataFromContext(ctx context.Context) (AuditMetadata, bool) {
	md, ok := ctx.Value(ctxKeyAuditMetadata).(AuditMetadata)
	return md, ok
}

// Service is the goroutine-backed Emitter. Construct it in theauth.New, call Start to run the
// writer, and Stop to drain it on shutdown.
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

	// inflight is the number of events in the batch currently being written
	// (0 when no flush is running); sinkWG joins the per-sink workers.
	inflight atomic.Int64
	// flushLimit and sinkQueue are the package defaults captured at
	// construction so a running Service never re-reads the globals.
	flushLimit time.Duration
	sinkQueue  int
	sinkWG     sync.WaitGroup

	// gapCount counts events dropped since the last gap marker. gapFirst and gapLast bound them. The
	// writer turns a non-zero count into a marker event.
	gapCount atomic.Uint64
	gapFirst atomic.Int64
	gapLast  atomic.Int64

	// hooks routes drop and queue depth metrics. It defaults to a no-op bundle, so the service works
	// without observability wiring.
	hooks         *obs.Hooks
	mDroppedTotal obs.Counter
	mQueueDepth   obs.Gauge
	mGapMarkers   obs.Counter
}

// NewService constructs a Service. cfg may be the zero value; Start applies
// defaults. The Service is not yet running until Start returns.
func NewService(storage Storage, cfg Config) *Service {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 4096
	}
	// The channels are created here, not in Start: Start flips started before
	// it could assign them, and a concurrent emit would read a nil channel.
	s := &Service{
		storage: storage,
		cfg:     cfg,
		hooks:   &obs.Hooks{},
		ch:      make(chan models.AuditEvent, bufSize),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),

		flushLimit: flushTimeout,
		sinkQueue:  sinkQueueSize,
	}
	s.mDroppedTotal = s.hooks.Counter(obs.MetricAuditDroppedTotal, nil)
	s.mQueueDepth = s.hooks.Gauge(obs.MetricAuditQueueDepth, nil)
	s.mGapMarkers = s.hooks.Counter(MetricAuditGapMarkersTotal, nil)
	return s
}

// SetHooks installs the observability bundle. Call it before Start so instruments bind to the live adapter.
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
	s.mGapMarkers = s.hooks.Counter(MetricAuditGapMarkersTotal, nil)
}

// Start spawns the writer goroutine. Idempotent: a second call is a no-op
// and returns nil. Safe to call after Stop has fully drained.
func (s *Service) Start() error {
	if !s.started.CompareAndSwap(false, true) {
		return nil
	}
	go s.writerLoop()
	return nil
}

// Stop closes the stop channel and waits up to DrainTimeout for the writer to drain. It is
// idempotent and a no-op before Start.
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
	if s.done == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return
	case <-timer.C:
	}
	// DrainTimeout elapsed while a write may still be in flight. Returning now could exit mid-write
	// and lose the batch, so keep waiting, bounded.
	if s.inflight.Load() > 0 {
		grace := time.NewTimer(s.flushLimit + time.Second)
		defer grace.Stop()
		select {
		case <-s.done:
			return
		case <-grace.C:
		}
	}
	lost := uint64(len(s.ch)) + uint64(max(s.inflight.Load(), 0))
	if lost > 0 {
		s.dropped.Add(lost)
	}
	slog.Warn("theauth: audit shutdown gave up before the writer drained",
		"dropped_at_shutdown", lost,
		"dropped_total", s.dropped.Load(),
	)
}

// EmitAudit satisfies Emitter. It is Emit with no overrides; Emit reads them from the context when present.
func (s *Service) EmitAudit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any) {
	s.Emit(ctx, action, target, metadata, nil, nil)
}

// Emit enqueues an audit event for batched async write. It never blocks and drops on overflow. The
// metadata map is mutated by the redactors, so callers must not keep references. Emit is a silent
// no-op before Start or after Stop.
func (s *Service) Emit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any, actorUser *models.ULID, actorSession *models.Session) {
	_ = s.emit(ctx, action, target, metadata, actorUser, actorSession)
}

// EmitDecision is Emit for decision-class events. With FailClosed set it returns
// ErrAuditUnavailable when the event cannot be queued, so the caller can deny the action. Otherwise
// it returns nil. It never blocks.
func (s *Service) EmitDecision(ctx context.Context, action string, target models.TargetRef, metadata map[string]any, actorUser *models.ULID, actorSession *models.Session) error {
	err := s.emit(ctx, action, target, metadata, actorUser, actorSession)
	if err != nil && s.cfg.FailClosed && s.isDecision(action) {
		return ErrAuditUnavailable
	}
	return nil
}

func (s *Service) isDecision(action string) bool {
	prefixes := s.cfg.DecisionActionPrefixes
	if len(prefixes) == 0 {
		prefixes = DefaultDecisionPrefixes
	}
	for _, p := range prefixes {
		if strings.HasPrefix(action, p) {
			return true
		}
	}
	return false
}

// recordDrop counts one dropped event and widens the gap window.
func (s *Service) recordDrop() {
	now := time.Now().UnixNano()
	s.dropped.Add(1)
	if s.gapCount.Add(1) == 1 {
		s.gapFirst.Store(now)
	}
	s.gapLast.Store(now)
	if s.mDroppedTotal != nil {
		s.mDroppedTotal.Inc()
	}
}

// emit queues the event. It returns ErrAuditUnavailable when the event was
// not queued (service not running, or buffer full and the event dropped).
func (s *Service) emit(ctx context.Context, action string, target models.TargetRef, metadata map[string]any, actorUser *models.ULID, actorSession *models.Session) error {
	if !s.started.Load() || s.closed.Load() {
		return ErrAuditUnavailable
	}
	if action == "" {
		return nil
	}
	s.emitted.Add(1)
	evt := models.AuditEvent{
		ID:         ulid.New(),
		Action:     action,
		TargetType: target.Type,
		TargetID:   target.ID,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
		// Not hashed. Unmapped actions keep an empty event; a context Event overrides below.
		Event: EventForAction(action),
	}
	// The custom redactor sees the raw metadata first. The default redactor runs afterwards unconditionally.
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
	// MetadataFromContext overrides the values supplied above. Root flows such as SCIM and SAML rely on this.
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
		evt.SubjectID = md.SubjectID
		evt.ActorID = md.ActorID
		evt.PolicyVersion = md.PolicyVersion
		evt.ApproverID = md.ApproverID
		if ValidEvent(md.Event) {
			evt.Event = md.Event
		}
		if len(md.DelegationChain) > 0 {
			evt.DelegationChain = append([]string(nil), md.DelegationChain...)
		}
		if len(md.InputProvenance) > 0 {
			prov := md.InputProvenance
			if s.cfg.CustomRedactor != nil {
				prov = s.cfg.CustomRedactor(prov)
			}
			if s.cfg.DefaultRedactor != nil {
				prov = s.cfg.DefaultRedactor(prov)
			}
			evt.InputProvenance = prov
		}
	}

	select {
	case s.ch <- evt:
		if s.mQueueDepth != nil {
			s.mQueueDepth.Set(float64(len(s.ch)))
		}
		return nil
	default:
		s.recordDrop()
		return ErrAuditUnavailable
	}
}

// Query returns up to q.Limit events and a cursor for the next page. The caller checks permissions;
// this method does no auth.
func (s *Service) Query(ctx context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	if err := CheckQuery(s.storage, q); err != nil {
		return nil, "", err
	}
	return s.storage.QueryAuditEvents(ctx, q)
}

// orderCapable is the optional flag a storage backend implements once it serves write order
// (storagetest.AuditOrderCapable).
type orderCapable interface{ AuditOrderSupported() bool }

// CheckQuery validates q before it reaches store: it returns ErrBadAuditOrder for an unknown order,
// ErrBadCursor for a "c1." cursor that does not decode for the query's order (or a legacy cursor
// combined with asc), and ErrAuditOrderUnsupported when the query needs write order support
// (asc, an Event filter or a "c1." cursor) and store does not declare AuditOrderSupported() true.
// A plain descending query with no event filter works on every backend.
func CheckQuery(store any, q models.AuditQuery) error {
	order, ok := NormalizeOrder(q.Order)
	if !ok {
		return models.ErrBadAuditOrder
	}
	legacy := IsLegacyCursor(q.After)
	if legacy && order != models.AuditOrderDesc {
		return fmt.Errorf("%w: legacy cursor needs desc order", models.ErrBadCursor)
	}
	if q.After != "" && !legacy {
		if _, err := DecodeCursor(q.After, order); err != nil {
			return err
		}
	}
	needs := order == models.AuditOrderAsc || q.Event != "" || (q.After != "" && !legacy)
	if !needs {
		return nil
	}
	if c, ok := store.(orderCapable); ok && c.AuditOrderSupported() {
		return nil
	}
	return models.ErrAuditOrderUnsupported
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

// writerLoop is the single goroutine that drains the channel, batches events by BatchSize or
// FlushInterval, and writes one batch at a time.
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
	queues := s.startSinkWorkers()
	defer func() {
		// Runs before close(s.done) (LIFO): let sink workers finish queued
		// batches so Stop's wait covers them.
		for _, q := range queues {
			close(q)
		}
		s.sinkWG.Wait()
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		// A burst of drops becomes one counted marker in the same batch, so
		// the stored chain shows where events are missing and how many.
		marked := s.gapCount.Swap(0)
		if marked > 0 {
			buf = append(buf, s.gapMarker(marked))
		}
		if len(buf) == 0 {
			return
		}
		// Detach from the request context; the writer owns a background
		// ctx so callers' cancellations cannot abort a batch in flight.
		ctx, cancel := context.WithTimeout(context.Background(), s.flushLimit)
		s.inflight.Store(int64(len(buf)))
		err := s.storage.InsertAuditEvents(ctx, buf)
		s.inflight.Store(0)
		cancel()
		if err != nil {
			s.failed.Add(uint64(len(buf)))
			slog.Error("theauth: audit insert failed", "count", len(buf), "err", err.Error())
			if marked > 0 {
				// The marker was not stored; keep the count for the next flush.
				s.gapCount.Add(marked)
			}
		} else {
			// The synthetic marker is not an emitted event, so it stays out of
			// the written counter and the emitted >= written + dropped invariant.
			if marked > 0 {
				s.written.Add(uint64(len(buf) - 1))
				if s.mGapMarkers != nil {
					s.mGapMarkers.Inc()
				}
			} else {
				s.written.Add(uint64(len(buf)))
			}
			// Fan out to each sink's bounded queue. The send never blocks the
			// writer: a sink that cannot keep up drops the batch (counted).
			if len(queues) > 0 {
				snapshot := make([]models.AuditEvent, len(buf))
				copy(snapshot, buf)
				for i, q := range queues {
					select {
					case q <- snapshot:
					default:
						s.sinkFailed.Add(1)
						slog.Warn("theauth: audit sink queue full, batch dropped",
							"sink", s.cfg.Sinks[i].Name(),
							"count", len(snapshot),
						)
					}
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

// gapMarker builds the synthetic event that records n dropped events.
func (s *Service) gapMarker(n uint64) models.AuditEvent {
	first := time.Unix(0, s.gapFirst.Load()).UTC()
	last := time.Unix(0, s.gapLast.Load()).UTC()
	return models.AuditEvent{
		ID:         ulid.New(),
		Action:     GapMarkerAction,
		TargetType: "audit",
		Event:      EventForAction(GapMarkerAction),
		Metadata: map[string]any{
			"dropped":         n,
			"firstDropped":    first.Format(time.RFC3339Nano),
			"lastDropped":     last.Format(time.RFC3339Nano),
			"droppedTotal":    s.dropped.Load(),
			"markerSynthetic": true,
		},
		CreatedAt: time.Now(),
	}
}

// startSinkWorkers starts one worker per sink, so sink goroutines are capped at len(Sinks). Sink
// failures are logged and dropped.
func (s *Service) startSinkWorkers() []chan []models.AuditEvent {
	queues := make([]chan []models.AuditEvent, len(s.cfg.Sinks))
	for i, sink := range s.cfg.Sinks {
		q := make(chan []models.AuditEvent, max(s.sinkQueue, 1))
		queues[i] = q
		s.sinkWG.Add(1)
		go func() {
			defer s.sinkWG.Done()
			for batch := range q {
				sinkCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if serr := sink.Stream(sinkCtx, batch); serr != nil {
					s.sinkFailed.Add(1)
					slog.Warn("theauth: audit sink failed",
						"sink", sink.Name(),
						"count", len(batch),
						"err", serr.Error(),
					)
				}
				cancel()
			}
		}()
	}
	return queues
}

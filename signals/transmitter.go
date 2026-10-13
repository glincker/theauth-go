package signals

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// TransmitterConfig configures a Transmitter.
type TransmitterConfig struct {
	// Issuer is the iss of every SET and of the metadata document.
	Issuer string
	// BaseURL is the public URL under which Handler is mounted (no trailing
	// slash), used to build endpoint URLs in the metadata document.
	BaseURL string
	// JWKSURI is advertised as jwks_uri so receivers can verify SETs.
	JWKSURI string
	// Signer signs SETs. Required.
	Signer Signer
	// Store holds streams and the queue. Default: a MemoryStore.
	Store Store
	// Authenticate resolves the calling receiver from the request (typically
	// by validating an OAuth access token). Required. The returned id owns
	// the streams it creates.
	Authenticate func(r *http.Request) (receiverID string, ok bool)

	// AllowPrivateNetworks and AllowInsecureHTTP relax push URL validation.
	// Both exist for tests and closed networks.
	AllowPrivateNetworks bool
	AllowInsecureHTTP    bool
	// Lookup overrides DNS resolution during URL validation (tests).
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// HTTPClient overrides the push client. The default refuses non-public
	// destinations at dial time and never follows redirects.
	HTTPClient *http.Client

	PushTimeout time.Duration // default 10s
	MaxAttempts int           // default 8
	BackoffBase time.Duration // default 2s, doubled per attempt
	BackoffMax  time.Duration // default 15m
	// PushInterval is how often Start scans the queue. Default 2s.
	PushInterval time.Duration
	// MaxPollEvents caps maxEvents on poll. Default 100.
	MaxPollEvents int
	// MaxPollWait caps long polling. Default 30s; 0 uses the default,
	// negative disables waiting.
	MaxPollWait time.Duration
	// MinVerificationInterval is advertised and enforced per stream.
	MinVerificationInterval time.Duration

	Clock  func() time.Time
	Logger *slog.Logger
}

// Transmitter serves the SSF management API and delivers SETs.
type Transmitter struct {
	cfg   TransmitterConfig
	store Store
	hc    *http.Client
	log   *slog.Logger

	nudge chan struct{}

	mu         sync.Mutex
	lastVerify map[string]time.Time
}

// NewTransmitter validates cfg and builds a Transmitter.
func NewTransmitter(cfg TransmitterConfig) (*Transmitter, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("signals: TransmitterConfig.Issuer is required")
	case cfg.BaseURL == "":
		return nil, errors.New("signals: TransmitterConfig.BaseURL is required")
	case cfg.Signer == nil:
		return nil, errors.New("signals: TransmitterConfig.Signer is required")
	case cfg.Authenticate == nil:
		return nil, errors.New("signals: TransmitterConfig.Authenticate is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.PushTimeout <= 0 {
		cfg.PushTimeout = 10 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 2 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 15 * time.Minute
	}
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 2 * time.Second
	}
	if cfg.MaxPollEvents <= 0 {
		cfg.MaxPollEvents = 100
	}
	if cfg.MaxPollWait == 0 {
		cfg.MaxPollWait = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	t := &Transmitter{cfg: cfg, store: cfg.Store, hc: cfg.HTTPClient, log: cfg.Logger,
		nudge: make(chan struct{}, 1), lastVerify: map[string]time.Time{}}
	if t.store == nil {
		t.store = NewMemoryStore()
	}
	if t.hc == nil {
		t.hc = safehttp.NewClient(cfg.PushTimeout, cfg.AllowPrivateNetworks)
	}
	if t.log == nil {
		t.log = slog.Default()
	}
	return t, nil
}

// Store returns the backing store.
func (t *Transmitter) Store() Store { return t.store }

func (t *Transmitter) urlPolicy() URLPolicy {
	return URLPolicy{AllowPrivate: t.cfg.AllowPrivateNetworks, AllowHTTP: t.cfg.AllowInsecureHTTP, Lookup: t.cfg.Lookup}
}

// Metadata returns the SSF transmitter metadata document (section 7.1).
func (t *Transmitter) Metadata() map[string]any {
	m := map[string]any{
		"spec_version":               "1_0",
		"issuer":                     t.cfg.Issuer,
		"delivery_methods_supported": []string{MethodPush, MethodPoll},
		"configuration_endpoint":     t.cfg.BaseURL + "/ssf/stream",
		"status_endpoint":            t.cfg.BaseURL + "/ssf/status",
		"add_subject_endpoint":       t.cfg.BaseURL + "/ssf/subjects/add",
		"remove_subject_endpoint":    t.cfg.BaseURL + "/ssf/subjects/remove",
		"verification_endpoint":      t.cfg.BaseURL + "/ssf/verify",
		"critical_subject_members":   []string{},
		"default_subjects":           "NONE",
	}
	if t.cfg.JWKSURI != "" {
		m["jwks_uri"] = t.cfg.JWKSURI
	}
	if t.cfg.MinVerificationInterval > 0 {
		m["min_verification_interval"] = int(t.cfg.MinVerificationInterval.Seconds())
	}
	return m
}

// Handler returns the transmitter routes. Mount it so that
// /.well-known/ssf-configuration is reachable at the issuer origin (with the
// issuer path suffix if the issuer has a path, per SSF section 7.2.1).
func (t *Transmitter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/ssf-configuration", t.handleMetadata)
	mux.HandleFunc("GET /.well-known/ssf-configuration/{path...}", t.handleMetadata)
	mux.HandleFunc("/ssf/stream", t.authed(t.handleStream))
	mux.HandleFunc("/ssf/status", t.authed(t.handleStatus))
	mux.HandleFunc("POST /ssf/subjects/add", t.authed(t.handleSubject(true)))
	mux.HandleFunc("POST /ssf/subjects/remove", t.authed(t.handleSubject(false)))
	mux.HandleFunc("POST /ssf/verify", t.authed(t.handleVerify))
	mux.HandleFunc("POST /ssf/poll/{id}", t.authed(t.handlePoll))
	return mux
}

type authedHandler func(w http.ResponseWriter, r *http.Request, receiver string)

func (t *Transmitter) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rcv, ok := t.cfg.Authenticate(r)
		if !ok || rcv == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssf"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		h(w, r, rcv)
	}
}

func (t *Transmitter) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(t.Metadata())
}

func writeErr(w http.ResponseWriter, code int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"err": errCode, "description": desc})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

// streamView is the management API representation (no secrets).
func (t *Transmitter) streamView(s Stream) map[string]any {
	d := map[string]any{"method": s.Delivery.Method}
	if s.Delivery.EndpointURL != "" {
		d["endpoint_url"] = s.Delivery.EndpointURL
	}
	v := map[string]any{
		"stream_id":                 s.ID,
		"iss":                       t.cfg.Issuer,
		"aud":                       s.Audience,
		"delivery":                  d,
		"events_supported":          SupportedEvents(),
		"events_requested":          orEmpty(s.EventsRequested),
		"events_delivered":          orEmpty(s.EventsDelivered),
		"min_verification_interval": int(t.cfg.MinVerificationInterval.Seconds()),
	}
	if s.Description != "" {
		v["description"] = s.Description
	}
	return v
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type streamRequest struct {
	StreamID        string   `json:"stream_id"`
	Aud             any      `json:"aud"`
	EventsRequested []string `json:"events_requested"`
	Description     *string  `json:"description"`
	Delivery        *struct {
		Method              string `json:"method"`
		EndpointURL         string `json:"endpoint_url"`
		AuthorizationHeader string `json:"authorization_header"`
	} `json:"delivery"`
}

func audList(v any) []string {
	switch a := v.(type) {
	case string:
		if a != "" {
			return []string{a}
		}
	case []any:
		var out []string
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (t *Transmitter) deliveredFor(requested []string) []string {
	if len(requested) == 0 {
		return SupportedEvents()
	}
	var out []string
	for _, e := range requested {
		if isSupported(e) {
			out = append(out, e)
		}
	}
	return out
}

// ownedStream loads a stream and hides streams of other receivers.
func (t *Transmitter) ownedStream(ctx context.Context, id, receiver string) (Stream, error) {
	s, err := t.store.GetStream(ctx, id)
	if err != nil {
		return Stream{}, err
	}
	if s.ReceiverID != receiver {
		return Stream{}, ErrNotFound
	}
	return s, nil
}

func (t *Transmitter) storeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "stream not found")
		return
	}
	t.log.Error("signals: store failure", "error", err)
	writeErr(w, http.StatusInternalServerError, "server_error", "internal error")
}

func (t *Transmitter) applyDelivery(ctx context.Context, s *Stream, d *struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url"`
	AuthorizationHeader string `json:"authorization_header"`
}) error {
	if d == nil {
		return nil
	}
	method := normalizeMethod(d.Method)
	if method == "" {
		return fmt.Errorf("unsupported delivery method %q", d.Method)
	}
	s.Delivery.Method = method
	switch method {
	case MethodPush:
		if err := ValidateEndpointURL(ctx, d.EndpointURL, t.urlPolicy()); err != nil {
			return err
		}
		s.Delivery.EndpointURL = d.EndpointURL
		s.Delivery.AuthorizationHeader = d.AuthorizationHeader
	case MethodPoll:
		s.Delivery.EndpointURL = t.cfg.BaseURL + "/ssf/poll/" + s.ID
		s.Delivery.AuthorizationHeader = ""
	}
	return nil
}

func (t *Transmitter) handleStream(w http.ResponseWriter, r *http.Request, receiver string) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		if id := r.URL.Query().Get("stream_id"); id != "" {
			s, err := t.ownedStream(ctx, id, receiver)
			if err != nil {
				t.storeErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, t.streamView(s))
			return
		}
		list, err := t.store.ListStreams(ctx, receiver)
		if err != nil {
			t.storeErr(w, err)
			return
		}
		views := make([]map[string]any, 0, len(list))
		for _, s := range list {
			views = append(views, t.streamView(s))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req streamRequest
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		now := t.cfg.Clock().UTC()
		s := Stream{ID: newID(), ReceiverID: receiver, Status: StatusEnabled, CreatedAt: now, UpdatedAt: now,
			EventsRequested: req.EventsRequested, Audience: audList(req.Aud)}
		if len(s.Audience) == 0 {
			s.Audience = []string{receiver}
		}
		if req.Description != nil {
			s.Description = *req.Description
		}
		if req.Delivery == nil {
			req.Delivery = &struct {
				Method              string `json:"method"`
				EndpointURL         string `json:"endpoint_url"`
				AuthorizationHeader string `json:"authorization_header"`
			}{Method: MethodPush}
		}
		if err := t.applyDelivery(ctx, &s, req.Delivery); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		s.EventsDelivered = t.deliveredFor(req.EventsRequested)
		if err := t.store.CreateStream(ctx, s); err != nil {
			t.storeErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, t.streamView(s))
	case http.MethodPatch, http.MethodPut:
		var req streamRequest
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		s, err := t.ownedStream(ctx, req.StreamID, receiver)
		if err != nil {
			t.storeErr(w, err)
			return
		}
		replace := r.Method == http.MethodPut
		if replace || req.EventsRequested != nil {
			s.EventsRequested = req.EventsRequested
			s.EventsDelivered = t.deliveredFor(req.EventsRequested)
		}
		if req.Description != nil {
			s.Description = *req.Description
		} else if replace {
			s.Description = ""
		}
		if a := audList(req.Aud); len(a) > 0 {
			s.Audience = a
		}
		if err := t.applyDelivery(ctx, &s, req.Delivery); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		s.UpdatedAt = t.cfg.Clock().UTC()
		if err := t.store.UpdateStream(ctx, s); err != nil {
			t.storeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, t.streamView(s))
	case http.MethodDelete:
		id := r.URL.Query().Get("stream_id")
		if _, err := t.ownedStream(ctx, id, receiver); err != nil {
			t.storeErr(w, err)
			return
		}
		if err := t.store.DeleteStream(ctx, id); err != nil {
			t.storeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PATCH, PUT, DELETE")
		writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

func (t *Transmitter) handleStatus(w http.ResponseWriter, r *http.Request, receiver string) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		s, err := t.ownedStream(ctx, r.URL.Query().Get("stream_id"), receiver)
		if err != nil {
			t.storeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"stream_id": s.ID, "status": s.Status})
	case http.MethodPost:
		var req struct {
			StreamID string `json:"stream_id"`
			Status   string `json:"status"`
			Reason   string `json:"reason"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		switch req.Status {
		case StatusEnabled, StatusPaused, StatusDisabled:
		default:
			writeErr(w, http.StatusBadRequest, "invalid_request", "status must be enabled, paused or disabled")
			return
		}
		s, err := t.ownedStream(ctx, req.StreamID, receiver)
		if err != nil {
			t.storeErr(w, err)
			return
		}
		s.Status, s.StatusReason, s.UpdatedAt = req.Status, req.Reason, t.cfg.Clock().UTC()
		if err := t.store.UpdateStream(ctx, s); err != nil {
			t.storeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"stream_id": s.ID, "status": s.Status})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

func (t *Transmitter) handleSubject(add bool) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, receiver string) {
		var req struct {
			StreamID string  `json:"stream_id"`
			Subject  Subject `json:"subject"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		ctx := r.Context()
		if _, err := t.ownedStream(ctx, req.StreamID, receiver); err != nil {
			t.storeErr(w, err)
			return
		}
		if err := req.Subject.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		var err error
		if add {
			raw, _ := json.Marshal(req.Subject)
			err = t.store.AddSubject(ctx, req.StreamID, req.Subject.Key(), raw)
		} else {
			err = t.store.RemoveSubject(ctx, req.StreamID, req.Subject.Key())
		}
		if err != nil {
			t.storeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (t *Transmitter) handleVerify(w http.ResponseWriter, r *http.Request, receiver string) {
	var req struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if _, err := t.ownedStream(r.Context(), req.StreamID, receiver); err != nil {
		t.storeErr(w, err)
		return
	}
	if err := t.Verify(r.Context(), req.StreamID, req.State); err != nil {
		if errors.Is(err, errTooFrequent) {
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "verification requested too often")
			return
		}
		t.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errTooFrequent = errors.New("signals: verification too frequent")

// Verify enqueues a verification event (SSF section 8.1.4.2) on a stream.
func (t *Transmitter) Verify(ctx context.Context, streamID, state string) error {
	s, err := t.store.GetStream(ctx, streamID)
	if err != nil {
		return err
	}
	now := t.cfg.Clock()
	if iv := t.cfg.MinVerificationInterval; iv > 0 {
		t.mu.Lock()
		last := t.lastVerify[streamID]
		if !last.IsZero() && now.Sub(last) < iv {
			t.mu.Unlock()
			return errTooFrequent
		}
		t.lastVerify[streamID] = now
		t.mu.Unlock()
	}
	props := map[string]any{}
	if state != "" {
		props["state"] = state
	}
	return t.enqueue(ctx, s, Event{Type: EventVerification, Properties: props})
}

// enqueue signs one SET carrying ev and queues it for s.
func (t *Transmitter) enqueue(ctx context.Context, s Stream, ev Event) error {
	now := t.cfg.Clock().UTC()
	set := SET{Issuer: t.cfg.Issuer, Audience: s.Audience, IssuedAt: now, JTI: newID(), Events: []Event{ev}}
	if len(set.Audience) == 0 {
		set.Audience = []string{s.ReceiverID}
	}
	tok, err := set.Sign(t.cfg.Signer)
	if err != nil {
		return err
	}
	err = t.store.Enqueue(ctx, PendingSET{ID: newID(), StreamID: s.ID, JTI: set.JTI, Token: tok,
		Push: s.IsPush(), NextAt: now, CreatedAt: now})
	if err == nil && s.IsPush() {
		select {
		case t.nudge <- struct{}{}:
		default:
		}
	}
	return err
}

// subjectMatches reports whether stream s wants events about sub: a stream
// with no registered subjects receives everything, otherwise the subject (or
// one member of a complex subject) must be registered.
func (t *Transmitter) subjectMatches(ctx context.Context, s Stream, sub Subject) (bool, error) {
	n, err := t.store.CountSubjects(ctx, s.ID)
	if err != nil {
		return false, err
	}
	if n == 0 || sub.IsZero() {
		return true, nil
	}
	keys := []string{sub.Key()}
	for _, m := range sub.Complex {
		keys = append(keys, m.Key())
	}
	for _, k := range keys {
		ok, err := t.store.HasSubject(ctx, s.ID, k)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Emit queues events on every enabled or paused stream that asked for the
// type and registered the subject. It returns the first error after trying
// all streams.
func (t *Transmitter) Emit(ctx context.Context, events ...Event) error {
	streams, err := t.store.ListStreams(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range streams {
		if s.Status == StatusDisabled {
			continue
		}
		for _, ev := range events {
			if !contains(s.EventsDelivered, ev.Type) {
				continue
			}
			ok, err := t.subjectMatches(ctx, s, ev.Subject)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !ok {
				continue
			}
			if err := t.enqueue(ctx, s, ev); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (t *Transmitter) handlePoll(w http.ResponseWriter, r *http.Request, receiver string) {
	ctx := r.Context()
	s, err := t.ownedStream(ctx, r.PathValue("id"), receiver)
	if err != nil {
		t.storeErr(w, err)
		return
	}
	if normalizeMethod(s.Delivery.Method) != MethodPoll {
		writeErr(w, http.StatusConflict, "invalid_request", "stream is not a poll stream")
		return
	}
	var req struct {
		Ack               []string `json:"ack"`
		MaxEvents         *int     `json:"maxEvents"`
		ReturnImmediately bool     `json:"returnImmediately"`
		SetErrs           map[string]struct {
			Err         string `json:"err"`
			Description string `json:"description"`
		} `json:"setErrs"`
	}
	if r.ContentLength != 0 {
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
	}
	toAck := append([]string(nil), req.Ack...)
	for jti, e := range req.SetErrs {
		t.log.Warn("signals: receiver rejected SET", "stream", s.ID, "jti", jti, "err", e.Err, "description", e.Description)
		toAck = append(toAck, jti)
	}
	if len(toAck) > 0 {
		if _, err := t.store.Ack(ctx, s.ID, toAck); err != nil {
			t.storeErr(w, err)
			return
		}
	}
	max := t.cfg.MaxPollEvents
	if req.MaxEvents != nil && *req.MaxEvents >= 0 && *req.MaxEvents < max {
		max = *req.MaxEvents
	}
	sets := map[string]string{}
	more := false
	if s.Status == StatusEnabled && max > 0 {
		deadline := t.cfg.Clock().Add(t.cfg.MaxPollWait)
		for {
			items, err := t.store.Pending(ctx, s.ID, max+1)
			if err != nil {
				t.storeErr(w, err)
				return
			}
			if len(items) > max {
				more = true
				items = items[:max]
			}
			for _, p := range items {
				sets[p.JTI] = p.Token
			}
			if len(sets) > 0 || req.ReturnImmediately || t.cfg.MaxPollWait < 0 || !t.cfg.Clock().Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": sets, "moreAvailable": more})
}

// StaticBearerAuth returns an Authenticate func that maps fixed bearer
// tokens to receiver ids using constant-time comparison.
func StaticBearerAuth(tokens map[string]string) func(*http.Request) (string, bool) {
	return func(r *http.Request) (string, bool) {
		h := r.Header.Get("Authorization")
		const p = "Bearer "
		if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
			return "", false
		}
		got := []byte(h[len(p):])
		for tok, id := range tokens {
			if subtle.ConstantTimeCompare(got, []byte(tok)) == 1 {
				return id, true
			}
		}
		return "", false
	}
}

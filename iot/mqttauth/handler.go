package mqttauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

const maxBodyBytes = 64 << 10

// Defaults applied by New.
const (
	DefaultCacheTTL        = 5 * time.Second
	DefaultCacheMaxEntries = 10000
	DefaultAllowSampleRate = 0.1
	DefaultCertHeader      = "X-Client-Cert-Fingerprint"
)

// Config configures a Handler.
type Config struct {
	// Store resolves devices. Required.
	Store DeviceStore
	// Authorizer decides publish and subscribe. Default RuleAuthorizer.
	Authorizer Authorizer
	// BrokerSecret is the bearer token the broker sends in the Authorization header. Certificate
	// fingerprints and the device_id attribute are only as trustworthy as the caller, so New
	// fails when this is empty unless AllowUnauthenticatedBroker is set (for a private loopback
	// or a network policy that already limits the caller).
	BrokerSecret               string
	AllowUnauthenticatedBroker bool
	// PurgeSecret enables POST /purge. Empty disables the endpoint (404).
	PurgeSecret string
	// JWT enables the JWT as password path. Nil disables it.
	JWT *JWTConfig
	// CertFingerprintHeader names the header carrying the client certificate SHA-256
	// fingerprint. Default DefaultCertHeader.
	CertFingerprintHeader string
	// AllowAnyClientID lifts the rule that the MQTT client ID is the device ID or starts with
	// the device ID followed by "-". The rule stops one device from taking over another's session.
	AllowAnyClientID bool
	// CacheTTL bounds how long a device record and an authorization decision are reused, and so
	// the revocation latency without a purge. Zero means DefaultCacheTTL, negative disables.
	CacheTTL        time.Duration
	CacheMaxEntries int
	// AllowSampleRate is the fraction of allow decisions sent to Audit, 0 means
	// DefaultAllowSampleRate, negative none, 1 all. Denies are always recorded.
	AllowSampleRate float64
	Audit           AuditSink
	// Mosquitto mounts the mosquitto-go-auth HTTP backend routes under /mosquitto/.
	Mosquitto bool
	Logger    *slog.Logger
	// Now and Rand are test hooks.
	Now  func() time.Time
	Rand func() float64
}

// Handler is the broker facing HTTP API. Routes, relative to where it is mounted:
//
//	POST /authn            EMQX authenticator
//	POST /authz            EMQX authorizer
//	POST /purge            drop cached state for {"device_id":"..."} or {"all":true}
//	POST /mosquitto/user, /mosquitto/superuser, /mosquitto/acl   when Config.Mosquitto is set
type Handler struct {
	cfg     Config
	mux     *http.ServeMux
	cache   *cache
	metrics counters
	log     *slog.Logger
	now     func() time.Time
	secret  [32]byte
	purge   [32]byte
}

// New validates cfg and returns a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("mqttauth: Config.Store is required")
	}
	if cfg.BrokerSecret == "" && !cfg.AllowUnauthenticatedBroker {
		return nil, errors.New("mqttauth: set Config.BrokerSecret, or AllowUnauthenticatedBroker when the network already restricts callers")
	}
	if cfg.JWT != nil {
		if err := cfg.JWT.validate(); err != nil {
			return nil, err
		}
	}
	if cfg.Authorizer == nil {
		cfg.Authorizer = RuleAuthorizer{}
	}
	if cfg.CertFingerprintHeader == "" {
		cfg.CertFingerprintHeader = DefaultCertHeader
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.CacheMaxEntries == 0 {
		cfg.CacheMaxEntries = DefaultCacheMaxEntries
	}
	if cfg.AllowSampleRate == 0 {
		cfg.AllowSampleRate = DefaultAllowSampleRate
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	h := &Handler{cfg: cfg, log: cfg.Logger, now: cfg.Now, mux: http.NewServeMux()}
	if h.log == nil {
		h.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h.cache = newCache(cfg.CacheTTL, cfg.CacheMaxEntries, cfg.Now)
	h.secret = sha256.Sum256([]byte(cfg.BrokerSecret))
	h.purge = sha256.Sum256([]byte(cfg.PurgeSecret))
	h.mux.HandleFunc("POST /authn", h.serveAuthn)
	h.mux.HandleFunc("POST /authz", h.serveAuthz)
	h.mux.HandleFunc("POST /purge", h.servePurge)
	if cfg.Mosquitto {
		h.mux.HandleFunc("POST /mosquitto/user", h.mosquittoUser)
		h.mux.HandleFunc("POST /mosquitto/superuser", h.mosquittoSuperuser)
		h.mux.HandleFunc("POST /mosquitto/acl", h.mosquittoACL)
	}
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// Purge forgets cached state for one device so a revocation applies at once. Call it from the
// code that revokes a device, or let an operator hit POST /purge.
func (h *Handler) Purge(deviceID string) int { return h.cache.purge(deviceID) }

// PurgeAll forgets all cached state.
func (h *Handler) PurgeAll() { h.cache.purgeAll() }

// brokerRequest is the union of the fields the supported brokers send.
type brokerRequest struct {
	Username        string          `json:"username"`
	Password        string          `json:"password"`
	ClientID        string          `json:"clientid"`
	Topic           string          `json:"topic"`
	Action          string          `json:"action"`
	Acc             json.RawMessage `json:"acc"`
	PeerHost        string          `json:"peerhost"`
	DeviceID        string          `json:"device_id"`
	CertFingerprint string          `json:"cert_fingerprint"`
}

func (h *Handler) brokerAuthorized(r *http.Request, want [32]byte, configured bool) bool {
	if !configured {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	g := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(g[:], want[:]) == 1
}

func (h *Handler) fromBroker(r *http.Request) bool {
	if h.cfg.AllowUnauthenticatedBroker && h.cfg.BrokerSecret == "" {
		return true
	}
	return h.brokerAuthorized(r, h.secret, true)
}

func readRequest(w http.ResponseWriter, r *http.Request) (brokerRequest, bool) {
	var req brokerRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return req, false
		}
		req = brokerRequest{
			Username: r.PostForm.Get("username"), Password: r.PostForm.Get("password"), ClientID: r.PostForm.Get("clientid"),
			Topic: r.PostForm.Get("topic"), Action: r.PostForm.Get("action"), PeerHost: r.PostForm.Get("peerhost"),
			DeviceID: r.PostForm.Get("device_id"), CertFingerprint: r.PostForm.Get("cert_fingerprint"),
		}
		if v := r.PostForm.Get("acc"); v != "" {
			req.Acc = json.RawMessage(v)
		}
		return req, true
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		return req, false
	}
	return req, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// emqxDeny answers a deny with status 200. EMQX treats 4xx and 5xx as "ignore" and moves on to
// the next authenticator, and for authorization an ignore falls through to authorization
// no_match, which defaults to allow. A deny must therefore always be an explicit 200.
func emqxDeny(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"result": "deny"}) }

func (h *Handler) record(ctx context.Context, e AuditEvent) {
	e.Time = h.now()
	h.metrics.inc("theauth_mqtt_"+e.Kind+"_total", verdictLabel(e.Allowed))
	if h.cfg.Audit == nil {
		return
	}
	if e.Allowed && h.cfg.AllowSampleRate < 1 && (h.cfg.AllowSampleRate < 0 || h.cfg.Rand() >= h.cfg.AllowSampleRate) {
		return
	}
	h.cfg.Audit.Record(ctx, e)
}

func verdictLabel(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func (h *Handler) servePurge(w http.ResponseWriter, r *http.Request) {
	if h.cfg.PurgeSecret == "" {
		http.NotFound(w, r)
		return
	}
	if !h.brokerAuthorized(r, h.purge, true) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		DeviceID string `json:"device_id"`
		All      bool   `json:"all"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.DeviceID == "") == !body.All {
		http.Error(w, "send either device_id or all", http.StatusBadRequest)
		return
	}
	n := 0
	if body.All {
		h.PurgeAll()
	} else {
		n = h.Purge(body.DeviceID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": n})
}

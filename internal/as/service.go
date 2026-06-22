package as

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/cimd"
	"github.com/glincker/theauth-go/internal/clientauthcache"
	"github.com/glincker/theauth-go/internal/dpop"
	"github.com/glincker/theauth-go/internal/models"
	obs "github.com/glincker/theauth-go/internal/observability"
)

// Service bundles the OAuth 2.1 authorization server runtime: JWKS state +
// rotation goroutine, introspection cache, client-auth Argon2id cache, and
// every per-request entry point (authorize, token, introspect, revoke,
// metadata, DCR, token-exchange).
//
// Constructed exactly once by *theauth.TheAuth.New when
// Config.AuthorizationServer is non-nil; root holds it on TheAuth.as and
// per-method forwarders delegate to the entry points below. Stop() is
// called by *TheAuth.Close so the rotation goroutine drains cleanly.
//
// The exported fields (Cfg, Storage, EncryptionKey, AgentPolicy) are
// configuration set at New time; the unexported fields are the runtime
// state. Root code (handlers, agent / delegation services that move in PR
// C / PR E) reads Cfg and Storage directly while we incrementally extract;
// no behavior change vs. the pre-PR-B *asState the field replaced.
type Service struct {
	// Cfg is the validated authorization server configuration. Read-only
	// after New. Exposed so root files that have not yet moved into a
	// dedicated internal package (handlers_oauth_server.go, service_agent.go,
	// service_delegation.go, handlers_account.go, handlers_admin_agents.go)
	// can read configuration the way the old *asState did.
	Cfg Config

	// Storage is the OAuthServerStorage adapter persisting AS state.
	// Exposed for the same reason as Cfg.
	Storage Storage

	// EncryptionKey is the 32-byte AES-256 key used to seal JWKS private
	// keys at rest. Not exposed via accessor; used internally by jwks.go.
	encryptionKey []byte

	// AgentPolicy is the subset of root *AgentConfig the AS needs at
	// token-exchange time. Nil when the deployment does not configure an
	// agent identity service; in that case ClientCredentialsToken and
	// ExchangeToken short-circuit with unsupported_grant_type.
	AgentPolicy *AgentPolicy

	// Audit is the back-reference to the root audit emitter so AS-issued
	// audit events flow through the same writer as the rest of the
	// service. Defaults to audit.NoopEmitter when wiring code passes nil.
	Audit audit.Emitter

	// AgentLookup resolves an "agent:<id>" subject claim back to the
	// owning Agent row. The implementation lives on the root *TheAuth
	// (service_agent.go::agentBySubjectClaim) which moves in PR C; for
	// now we depend on the interface so internal/as never references the
	// root package.
	AgentLookup AgentLookup

	// signingKeys is the in-memory snapshot of the JWKS state machine.
	// The rotation goroutine swaps it atomically under mu.
	mu           sync.RWMutex
	keys         []models.JWKSKey
	keyMap       map[string]models.JWKSKey
	privKeyByKID map[string]ed25519.PrivateKey

	rotationStop chan struct{}
	rotationDone chan struct{}

	// introspectCache memoizes recent introspection responses keyed by
	// token hash. Honors IntrospectionCacheTTL.
	introspectCache sync.Map // map[string]*introspectCacheEntry

	// chainCache memoizes the result of chainStillActive keyed by the
	// outermost agent ID string. Bounded staleness: entries older than 5s
	// are re-walked. Invalidated by InvalidateChainCache on suspend/revoke
	// (perf re-audit 2026-06-21, item 3).
	chainCache sync.Map // map[string]*chainCacheEntry

	// clientAuthCache memoizes the result of an Argon2id verify on
	// client_secret_hash. Keyed by client_id; cached entries bind the
	// verified *OAuthClient snapshot to the sha256 of the presented secret.
	clientAuthCache *clientauthcache.Cache[*models.OAuthClient]

	// cimdSvc resolves https-URL client_ids per the MCP authorization
	// spec 2025-11-25 (Client ID Metadata Documents). Nil when CIMD is
	// not configured; in that case ResolveClient falls through to the
	// legacy OAuthClientByClientID path for every client_id.
	cimdSvc *cimd.Service

	// dpopSvc is the RFC 9449 proof verifier. nil when Cfg.DPoP is nil
	// (DPoP disabled); the token endpoint short-circuits dpop handling
	// in that case and never reads from this field.
	dpopSvc *dpop.Service

	// Hooks is the consumer-supplied observability bundle. Never nil:
	// New substitutes the no-op bundle when Deps.Hooks is nil. Every
	// instrumented path uses Hooks.StartSpan / Hooks.Counter directly so
	// nil-checks live at the bundle level, not at every emit site.
	Hooks *obs.Hooks

	// cached instruments owned by the AS service. Constructed once at
	// New time so the hot paths (token, introspect) do not pay a map
	// lookup on every request. Each instrument is created with a fixed
	// label SET; per-call label VALUES still flow through the factory
	// (the adapter is expected to cache the resulting child instrument).
	mIntrospectLatency obs.Histogram
	mCacheSizeGauge    obs.Gauge
}

// introspectCacheEntry holds one cached introspection response body plus
// its expiry deadline. Replaced wholesale on cache miss; never mutated.
type introspectCacheEntry struct {
	expiresAt time.Time
	body      []byte
}

// chainCacheEntry holds the result of one chainStillActive walk keyed by
// the outermost agent ID. Entries are considered stale after 5 seconds
// (matching the spirit of IntrospectionCacheTTL but kept short enough to
// make revocation observable quickly). Invalidated explicitly on
// suspend/revoke via InvalidateChainCache (perf re-audit 2026-06-21,
// item 3).
type chainCacheEntry struct {
	active    bool
	checkedAt time.Time
}

// chainCacheTTL is the maximum age for a chain-cache entry. Kept at 5s
// so revocation propagation lags the operator decision by at most one
// re-audit window rather than the full IntrospectionCacheTTL.
const chainCacheTTL = 5 * time.Second

// AgentLookup resolves an "agent:<id>" sub or act.sub claim into the
// underlying Agent row. Implementations live outside the as package
// because the agent identity service is owned by root (and moves in PR C).
type AgentLookup interface {
	// AgentBySubjectClaim parses the supplied claim and returns the agent
	// row. Returns (nil, nil) when the claim does not name an agent so
	// callers can branch cleanly. Returns (nil, models.ErrAgentNotFound)
	// when the claim names an agent that does not exist.
	AgentBySubjectClaim(ctx context.Context, sub string) (*models.Agent, error)
}

// AgentLookupFunc is a func adapter that lets root wire its own method
// (TheAuth.agentBySubjectClaim) without declaring an explicit type.
type AgentLookupFunc func(ctx context.Context, sub string) (*models.Agent, error)

// AgentBySubjectClaim satisfies AgentLookup by calling the underlying
// function. Returns (nil, nil) when the function is nil so the optional
// dependency stays optional at no extra wiring cost.
func (f AgentLookupFunc) AgentBySubjectClaim(ctx context.Context, sub string) (*models.Agent, error) {
	if f == nil {
		return nil, nil
	}
	return f(ctx, sub)
}

// Deps bundles the constructor inputs so New stays readable as the
// authorization server picks up more knobs in future phases.
type Deps struct {
	Cfg           Config
	Storage       Storage
	EncryptionKey []byte
	AgentPolicy   *AgentPolicy
	Audit         audit.Emitter
	AgentLookup   AgentLookup
	// Hooks wires the consumer-supplied tracer + metrics adapters. MAY
	// be nil; New substitutes the no-op bundle.
	Hooks *obs.Hooks
}

// New constructs a Service. The supplied Config must already have been
// validated via Validate(). The Service is inert until Start is called;
// Start bootstraps the JWKS state and launches the rotation goroutine.
func New(d Deps) *Service {
	emitter := d.Audit
	if emitter == nil {
		emitter = audit.NoopEmitter{}
	}
	var dpopSvc *dpop.Service
	if d.Cfg.DPoP != nil {
		// Validate already ran in Validate(); if New is called directly
		// the dpop.New constructor will reapply defaults so we never
		// land on a zero-valued config.
		ds, err := dpop.New(*d.Cfg.DPoP)
		if err == nil {
			dpopSvc = ds
		}
	}
	hooks := d.Hooks
	if hooks == nil {
		hooks = &obs.Hooks{}
	}
	s := &Service{
		Cfg:             d.Cfg,
		Storage:         d.Storage,
		encryptionKey:   d.EncryptionKey,
		AgentPolicy:     d.AgentPolicy,
		Audit:           emitter,
		AgentLookup:     d.AgentLookup,
		keyMap:          map[string]models.JWKSKey{},
		privKeyByKID:    map[string]ed25519.PrivateKey{},
		clientAuthCache: clientauthcache.New[*models.OAuthClient](clientauthcache.DefaultMaxEntries, clientauthcache.DefaultTTL),
		dpopSvc:         dpopSvc,
		Hooks:           hooks,
	}
	if d.Cfg.CIMD != nil {
		s.cimdSvc = cimd.NewService(*d.Cfg.CIMD, emitter)
	}
	// Pre-allocate the instruments with stable label sets so the hot
	// path (introspect, clientauthcache size gauge) does not allocate
	// per request. Per-request label VALUES that vary (grant_type,
	// status) are looked up at emit time below.
	s.mIntrospectLatency = hooks.Histogram(obs.MetricOAuthIntrospectLatency, obs.Labels{}, obs.LatencyBuckets)
	s.mCacheSizeGauge = hooks.Gauge(obs.MetricClientAuthCacheSize, obs.Labels{"kind": "oauth_client"})
	return s
}

// DPoP returns the underlying DPoP verifier or nil when DPoP is
// disabled. Exposed so handlers in internal/as/handlers can call
// IssueNonce / Verify without round-tripping through the Service.
func (s *Service) DPoP() *dpop.Service {
	if s == nil {
		return nil
	}
	return s.dpopSvc
}

// Start bootstraps the JWKS state (loading existing keys or minting fresh
// ones) and launches the rotation goroutine when DisableRotation is false.
// Safe to call multiple times; the rotation goroutine is gated by a
// non-nil rotationStop channel so a second call after Stop is a no-op.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if err := s.bootstrapJWKS(ctx); err != nil {
		return err
	}
	if s.cimdSvc != nil {
		s.cimdSvc.Start()
	}
	if s.Cfg.DisableRotation {
		return nil
	}
	s.rotationStop = make(chan struct{})
	s.rotationDone = make(chan struct{})
	go s.jwksRotationLoop()
	return nil
}

// Stop shuts the rotation goroutine and waits for it to finish. Idempotent.
func (s *Service) Stop() {
	if s == nil {
		return
	}
	if s.cimdSvc != nil {
		s.cimdSvc.Stop()
	}
	if s.rotationStop == nil {
		return
	}
	select {
	case <-s.rotationStop:
		// already closed
	default:
		close(s.rotationStop)
	}
	if s.rotationDone != nil {
		select {
		case <-s.rotationDone:
		case <-time.After(5 * time.Second):
			slog.Warn("theauth: JWKS rotation goroutine did not drain in 5s")
		}
	}
}

// InvalidateClientAuthCache drops the cached Argon2-verified entry for
// clientID. Called from every code path that rotates or removes the
// stored client_secret_hash so a freshly minted secret is never shadowed
// by a stale verified entry and a deleted client cannot continue
// authenticating from cache.
func (s *Service) InvalidateClientAuthCache(clientID string) {
	if s == nil || s.clientAuthCache == nil {
		return
	}
	s.clientAuthCache.Invalidate(clientID)
	s.updateCacheSizeGauge()
}

// InvalidateChainCache drops the cached chainStillActive result for the
// supplied agent ID string. Must be called whenever an agent's status
// changes to suspended or revoked so the next introspection re-walks the
// chain and does not serve a stale "active" answer (perf re-audit
// 2026-06-21, item 3).
func (s *Service) InvalidateChainCache(agentID string) {
	if s == nil || agentID == "" {
		return
	}
	s.chainCache.Delete(agentID)
}

// ResolveClient looks up an OAuth client by client_id, routing through
// the CIMD service when the client_id parses as an https URL, otherwise
// falling through to the storage-backed DCR registration.
//
// Per the MCP authorization spec 2025-11-25, an https-shaped client_id
// is canonically a CIMD URL. We honor that signal with no fallback:
//
//   - CIMD configured + policy allows: fetch the document, validate,
//     synthesize an OAuthClient. Cache honors CIMDConfig.CacheTTL.
//   - CIMD configured + policy denies: invalid_client. No silent fall
//     through to storage; that would let a malicious client publish a
//     URL whose host the operator does not trust and still authenticate
//     by happening to have the same string registered as a DCR
//     client_id.
//   - CIMD not configured (Cfg.CIMD == nil) and client_id is an https
//     URL: invalid_client. Same downgrade-attack reasoning. Operators
//     who want to disable CIMD altogether should also reject https-
//     shaped client_ids; allowing them through to storage opens the
//     same hole.
//   - Otherwise (client_id is an opaque string like "client-01J..."):
//     consult Storage.OAuthClientByClientID. This is the v2.0 phase 1+2
//     DCR path, unchanged.
func (s *Service) ResolveClient(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	if s == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	if clientID == "" {
		return nil, models.ErrOAuthInvalidClient
	}
	if cimd.LooksLikeCIMD(clientID) {
		if s.cimdSvc == nil {
			return nil, models.ErrOAuthInvalidClient
		}
		client, err := s.cimdSvc.Resolve(ctx, clientID)
		if err != nil {
			return nil, models.ErrOAuthInvalidClient
		}
		return client, nil
	}
	return s.Storage.OAuthClientByClientID(ctx, clientID)
}

// ResourceByIdentifier returns the configured ProtectedResource matching
// the supplied identifier, or false when not found. Identifier matching
// is case sensitive and trims a single trailing slash on the input to
// absorb caller inconsistency.
func (s *Service) ResourceByIdentifier(id string) (models.ProtectedResource, bool) {
	if s == nil {
		return models.ProtectedResource{}, false
	}
	id = strings.TrimRight(id, "/")
	for _, r := range s.Cfg.Resources {
		canonical := strings.TrimRight(r.Identifier, "/")
		if canonical == id {
			return r, true
		}
	}
	return models.ProtectedResource{}, false
}

// validateScopeAgainstResource returns the intersection of requested and
// supported scopes; returns error if requested contains any scope outside
// the resource's catalog. Mirror of root validateScopeAgainstResource.
func validateScopeAgainstResource(requested []string, resource models.ProtectedResource) ([]string, error) {
	if len(requested) == 0 {
		return nil, errors.New("scope required")
	}
	if len(resource.Scopes) == 0 {
		return requested, nil
	}
	supported := map[string]struct{}{}
	for _, s := range resource.Scopes {
		supported[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := supported[s]; !ok {
			return nil, models.ErrOAuthInvalidScope
		}
		out = append(out, s)
	}
	return out, nil
}

// scopeSubset reports whether every element of sub is present in sup.
func scopeSubset(sub, sup []string) bool {
	have := map[string]struct{}{}
	for _, s := range sup {
		have[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

// scopeJoin renders a scope slice as the space-separated form used in JWT
// claims, RFC 7591 client metadata, and Cache-Control responses.
func scopeJoin(scope []string) string { return strings.Join(scope, " ") }

// scopeSplit parses a space-separated scope string into a deduped slice
// preserving order of first occurrence.
func scopeSplit(s string) []string {
	parts := strings.Fields(s)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// errAuthorizeLoginRequired is the sentinel returned by StartAuthorize
// when the user is anonymous. Root maps this to a redirect to LoginURL.
var errAuthorizeLoginRequired = errors.New("theauth: authorize requires user session")

// IsLoginRequired reports whether the supplied error signals the
// authorize path needs an authenticated user. Mirror of the root
// IsLoginRequired; both must agree on the sentinel value, so the root
// version simply delegates here.
func IsLoginRequired(err error) bool {
	return errors.Is(err, errAuthorizeLoginRequired)
}

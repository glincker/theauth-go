package as

import (
	"context"
	"crypto"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/clientauthcache"
	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/internal/models"
	obs "github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/glincker/theauth-go/v2/kv"
)

// Service is the OAuth 2.1 authorization server runtime: JWKS state and rotation, introspection and
// client-auth caches, and every per-request entry point. Constructed once by theauth.New; Stop runs
// from Close.
type Service struct {
	// Cfg is the validated AS configuration, read-only after New.
	Cfg Config

	// Storage persists the AS state.
	Storage Storage

	// EncryptionKey seals JWKS private keys at rest.
	encryptionKey []byte

	// AgentPolicy is what the AS needs from the agent config at token-exchange time. Nil means no
	// agent identity service.
	AgentPolicy *AgentPolicy

	// Audit is the audit emitter shared with the rest of the service. Nil wiring gets audit.NoopEmitter.
	Audit audit.Emitter

	// AgentLookup resolves an "agent:<id>" subject back to its Agent row, keeping this package free of the root.
	AgentLookup AgentLookup

	// AgentGate, when set, vets every agent token mint against the agent's policies and rate limit.
	AgentGate AgentGate

	// signingKeys is the in-memory snapshot of the JWKS state machine, swapped atomically under mu.
	mu           sync.RWMutex
	keys         []models.JWKSKey
	keyMap       map[string]models.JWKSKey
	privKeyByKID map[string]crypto.Signer
	pubByKID     map[string]verifyKey

	// rotationMu serialises RotateSigningKey so concurrent callers never see two rows both marked
	// current. The storage transaction (JWKSAtomicRotator) gives the database-level guarantee; this
	// mutex covers the process.
	rotationMu sync.Mutex

	rotationStop chan struct{}
	rotationDone chan struct{}

	// introspectCache memoizes introspection responses by token hash, honoring IntrospectionCacheTTL.
	introspectCache sync.Map // map[string]*introspectCacheEntry

	// chainCache memoizes chainStillActive results by outermost agent ID. Entries expire after 5s and
	// are dropped on suspend or revoke, so revocation is seen quickly.
	chainCache sync.Map // map[string]*chainCacheEntry

	// subjectCache memoizes positive subjectActive answers for Cfg.SubjectActiveCacheTTL.
	subjectCache sync.Map // map[string]time.Time

	// clientAuthCache memoizes an Argon2id verify of client_secret_hash. Entries bind the verified
	// client to the sha256 of the presented secret.
	clientAuthCache *clientauthcache.Cache[*models.OAuthClient]

	// cimdSvc resolves https client_ids as Client ID Metadata Documents. Nil when CIMD is off.
	cimdSvc *cimd.Service

	// consentReplay records used consent tickets, which are single use.
	consentReplay kv.ReplayCache

	// dpopSvc verifies RFC 9449 proofs. Nil when DPoP is disabled.
	dpopSvc *dpop.Service

	// jwtBearerStorage is the durable JTI replay cache when the root Storage supports it. Otherwise
	// jtiCache is used.
	jwtBearerStorage JWTBearerStorageAdapter

	// jwks fetches and caches remote JWKS documents behind an SSRF guard.
	jwks *jwksFetcher

	// jtiCache is the in-process JTI replay fallback, keyed by "client:<jti>" or "grant:<jti>".
	jtiCache sync.Map // map[string]time.Time

	// Limiter backs the per-IP and per-client limits on AS endpoints. Never nil after New.
	Limiter kv.RateLimiter

	// verifySem caps concurrent Argon2id client-secret verifications. Nil when the cap is off.
	verifySem chan struct{}

	// Users resolves local users for userinfo and logout tokens. Nil disables userinfo.
	Users UserLookup

	// oidcCache holds session linkage state for OIDC logout.
	oidcCache kv.Cache

	// logoutWG tracks in-flight back-channel logout deliveries.
	logoutWG sync.WaitGroup

	// Hooks is the observability bundle. Never nil: New substitutes a no-op bundle.
	Hooks *obs.Hooks

	// Instruments created once at New so hot paths do not look them up per request. Label sets are
	// fixed; label values are supplied at emit time.
	mIntrospectLatency obs.Histogram
	mCacheSizeGauge    obs.Gauge
}

// introspectCacheEntry is one cached introspection body and its expiry. It is replaced on miss,
// never mutated.
type introspectCacheEntry struct {
	expiresAt time.Time
	body      []byte
}

// chainCacheEntry is one chainStillActive result keyed by the outermost agent ID. It goes stale
// after 5 seconds, so revocation becomes visible quickly; InvalidateChainCache drops it on suspend
// or revoke.
type chainCacheEntry struct {
	active    bool
	checkedAt time.Time
	// expiresAt is the earliest agent expiry in the walked chain, zero when none.
	expiresAt time.Time
}

// chainCacheTTL is the maximum age of a chain-cache entry. It is short so revocation lags the
// operator decision by little.
const chainCacheTTL = 5 * time.Second

// AgentLookup resolves an "agent:<id>" sub or act.sub claim to its Agent row.
type AgentLookup interface {
	// AgentBySubjectClaim returns the agent for the claim. (nil, nil) means the claim names no agent; (nil,
	// models.ErrAgentNotFound) means it names a missing agent.
	AgentBySubjectClaim(ctx context.Context, sub string) (*models.Agent, error)
}

// AgentLookupFunc adapts a function to AgentLookup, so root can wire a method directly.
type AgentLookupFunc func(ctx context.Context, sub string) (*models.Agent, error)

// AgentBySubjectClaim calls the function. A nil function returns (nil, nil), keeping the dependency optional.
func (f AgentLookupFunc) AgentBySubjectClaim(ctx context.Context, sub string) (*models.Agent, error) {
	if f == nil {
		return nil, nil
	}
	return f(ctx, sub)
}

// Deps bundles the constructor inputs so New stays readable as knobs are added.
type Deps struct {
	Cfg           Config
	Storage       Storage
	EncryptionKey []byte
	AgentPolicy   *AgentPolicy
	Audit         audit.Emitter
	AgentLookup   AgentLookup
	// JWTBearerStorage, when non-nil, backs the JTI replay cache durably.
	JWTBearerStorage JWTBearerStorageAdapter
	// Hooks is the observability adapters. May be nil; New substitutes the no-op bundle.
	Hooks *obs.Hooks
	// Users resolves local users for the OIDC userinfo endpoint.
	Users UserLookup
}

// New constructs a Service from a validated Config. The Service is inert until Start.
func New(d Deps) *Service {
	emitter := d.Audit
	if emitter == nil {
		emitter = audit.NoopEmitter{}
	}
	var dpopSvc *dpop.Service
	if d.Cfg.DPoP != nil {
		// dpop.New reapplies defaults, so a zero-valued config is never used even if Validate was skipped.
		dc := *d.Cfg.DPoP
		if dc.ReplayCache == nil {
			dc.ReplayCache = d.Cfg.Stores.ReplayCache
		}
		ds, err := dpop.New(dc)
		if err == nil {
			dpopSvc = ds
		}
	}
	hooks := d.Hooks
	if hooks == nil {
		hooks = &obs.Hooks{}
	}
	s := &Service{
		Cfg:              d.Cfg,
		Storage:          d.Storage,
		encryptionKey:    d.EncryptionKey,
		AgentPolicy:      d.AgentPolicy,
		Audit:            emitter,
		AgentLookup:      d.AgentLookup,
		keyMap:           map[string]models.JWKSKey{},
		privKeyByKID:     map[string]crypto.Signer{},
		pubByKID:         map[string]verifyKey{},
		clientAuthCache:  clientauthcache.New[*models.OAuthClient](clientauthcache.DefaultMaxEntries, clientauthcache.DefaultTTL),
		dpopSvc:          dpopSvc,
		jwtBearerStorage: d.JWTBearerStorage,
		jwks:             newJWKSFetcher(d.Cfg.JWTBearer),
		Users:            d.Users,
		Hooks:            hooks,
	}
	if s.Cfg.Clock == nil {
		s.Cfg.Clock = realClock{}
	}
	if s.Cfg.DeviceTokens != nil {
		dc := *s.Cfg.DeviceTokens
		applyDeviceTokenDefaults(&dc)
		s.Cfg.DeviceTokens = &dc
	}
	if s.Cfg.OIDC != nil {
		oc := *s.Cfg.OIDC
		applyOIDCDefaults(&oc, s.Cfg.AccessTokenTTL)
		s.Cfg.OIDC = &oc
		s.oidcCache = d.Cfg.Stores.Cache
		if s.oidcCache == nil {
			s.oidcCache = kv.NewMemory()
		}
	}
	if s.Cfg.ConsentHandler != nil {
		s.consentReplay = d.Cfg.Stores.ReplayCache
		if s.consentReplay == nil {
			s.consentReplay = kv.NewMemory()
		}
	}
	applyRateLimitDefaults(&s.Cfg)
	if n := s.Cfg.RateLimits.MaxConcurrentSecretVerifications; n > 0 {
		s.verifySem = make(chan struct{}, n)
	}
	s.Limiter = d.Cfg.Stores.RateLimiter
	if s.Limiter == nil {
		s.Limiter = kv.NewMemory()
	}
	if d.Cfg.CIMD != nil {
		cc := *d.Cfg.CIMD
		if cc.Cache == nil {
			cc.Cache = d.Cfg.Stores.Cache
		}
		s.cimdSvc = cimd.NewService(cc, emitter)
	}
	// Instruments are allocated up front so the hot path does not allocate per request.
	s.mIntrospectLatency = hooks.Histogram(obs.MetricOAuthIntrospectLatency, obs.Labels{}, obs.LatencyBuckets)
	s.mCacheSizeGauge = hooks.Gauge(obs.MetricClientAuthCacheSize, obs.Labels{"kind": "oauth_client"})
	return s
}

// DPoP returns the DPoP verifier, or nil when DPoP is disabled.
func (s *Service) DPoP() *dpop.Service {
	if s == nil {
		return nil
	}
	return s.dpopSvc
}

// TokenEndpointURL is the canonical token endpoint URL derived from the issuer. It is the expected
// DPoP htu and the client-assertion audience (RFC 7523 section 3).
func (s *Service) TokenEndpointURL() string { return s.tokenEndpointURL() }

func (s *Service) tokenEndpointURL() string {
	if s == nil {
		return ""
	}
	return s.Cfg.Issuer + "/oauth/token"
}

// Start bootstraps the JWKS state and launches the rotation goroutine unless DisableRotation is
// set. Calling it again is safe.
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

// Stop shuts the rotation goroutine and waits for it. Idempotent.
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

// InvalidateClientAuthCache drops the verified-secret cache entry for clientID. It runs on every
// secret rotation or client removal, so a stale entry can never authenticate.
func (s *Service) InvalidateClientAuthCache(clientID string) {
	if s == nil || s.clientAuthCache == nil {
		return
	}
	s.clientAuthCache.Invalidate(clientID)
	s.updateCacheSizeGauge()
}

// InvalidateChainCache drops the cached chain result for an agent. It must run when an agent is
// suspended or revoked, so the next introspection re-walks the chain.
func (s *Service) InvalidateChainCache(agentID string) {
	if s == nil || agentID == "" {
		return
	}
	s.chainCache.Delete(agentID)
	s.InvalidateSubject(models.AgentSubjectPrefix + agentID)
}

// ResolveClient looks up an OAuth client by client_id. An https-shaped client_id is a CIMD URL per
// the MCP spec 2025-11-25, so it goes to the CIMD service with no fallback. Other ids use
// storage-backed DCR registration.
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

// ResourceByIdentifier returns the configured ProtectedResource with the given identifier. Matching
// is case sensitive and tolerates one trailing slash.
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

// validateScopeAgainstResource returns the requested scopes intersected with the resource catalog.
// It errors on any scope outside the catalog.
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

// scopeJoin renders scopes in the space-separated form used by JWT claims and client metadata.
func scopeJoin(scope []string) string { return strings.Join(scope, " ") }

// scopeSplit parses a space-separated scope string into a deduped slice, keeping first occurrences in order.
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

// errAuthorizeLoginRequired is returned by StartAuthorize for an anonymous user. The root maps it
// to a redirect to LoginURL.
var errAuthorizeLoginRequired = errors.New("theauth: authorize requires user session")

// IsLoginRequired reports whether err is errAuthorizeLoginRequired. The root version delegates here
// so both agree on the sentinel.
func IsLoginRequired(err error) bool {
	return errors.Is(err, errAuthorizeLoginRequired)
}

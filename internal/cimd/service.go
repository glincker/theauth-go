package cimd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/kv"
)

// Default knobs for a zero Config: a small fetch budget and a short cache TTL, so a publisher's
// policy change propagates quickly.
const (
	// DefaultFetchTimeout caps one outbound CIMD fetch.
	DefaultFetchTimeout = 5 * time.Second
	// DefaultCacheTTL is how long a validated document stays usable
	// before the next request triggers a re-fetch.
	DefaultCacheTTL = 5 * time.Minute
	// DefaultMaxDocumentBytes caps a CIMD document body at 5 KiB, following the draft recommendation.
	// Raise Config.MaxDocumentBytes if needed.
	DefaultMaxDocumentBytes int64 = 5 * 1024
	// DefaultNegativeCacheTTL remembers a failed fetch, so a broken or hostile client_id cannot force
	// a refetch on every request.
	DefaultNegativeCacheTTL = 30 * time.Second
	// gcEvery is how often the cache GC sweep runs. 60s mirrors other
	// in-tree GC loops (webauthn challenges, oauth state).
	gcEvery = time.Minute
	// MinCacheTTL floors the window that HonorCacheControl can shorten, so max-age=0 cannot force a
	// fetch on every request.
	MinCacheTTL = 10 * time.Second
)

// Config wires the CIMD service. All fields are optional; missing values use the package defaults.
type Config struct {
	// TrustPolicy decides which https URLs may be fetched. Nil means DenyAll, so CIMD needs an
	// explicit allow policy to work.
	TrustPolicy TrustPolicy

	// FetchTimeout caps one outbound HTTP fetch. Zero applies
	// DefaultFetchTimeout.
	FetchTimeout time.Duration

	// CacheTTL caps how long a validated document stays usable before
	// re-fetch. Zero applies DefaultCacheTTL.
	CacheTTL time.Duration

	// MaxDocumentBytes caps a document body. Zero uses DefaultMaxDocumentBytes; negative disables the
	// cap (not advised publicly).
	MaxDocumentBytes int64

	// NegativeCacheTTL remembers failed fetches. Zero uses DefaultNegativeCacheTTL; negative disables
	// the negative cache.
	NegativeCacheTTL time.Duration

	// HTTPClient performs outbound fetches. Nil builds an SSRF-guarded client (no redirects,
	// non-public addresses refused at dial). A supplied client is used as is, so it must give
	// equivalent protection.
	HTTPClient *http.Client

	// AllowPrivateNetworks disables the dial-time block on non-public addresses. Development only: it
	// re-opens SSRF.
	AllowPrivateNetworks bool

	// Cache, when set, is a second tier shared by every replica. Documents read from it are still re-validated.
	Cache kv.Cache

	// DenyHost, when set, is consulted before any network IO; returning
	// true rejects the URL's hostname. It runs in addition to TrustPolicy.
	DenyHost func(host string) bool

	// HonorCacheControl lets the publisher shorten caching with max-age, no-store or no-cache, clamped
	// to [MinCacheTTL, CacheTTL]. A publisher can never extend caching past CacheTTL. Off by default.
	HonorCacheControl bool

	// AllowPrivateNetworks disables the dial-time block on non-public addresses. Development only: it
	// re-opens SSRF.
	AllowedRedirectSchemes []string
}

// forbiddenRedirectSchemes can never be allowed as redirect schemes: they
// execute in or navigate a browser context or reach local files.
var forbiddenRedirectSchemes = map[string]struct{}{
	"http": {}, "https": {}, "javascript": {}, "data": {}, "file": {},
	"vbscript": {}, "blob": {}, "about": {}, "ftp": {},
}

// Validate checks AllowedRedirectSchemes: each entry must be a lowercase
// URI scheme (RFC 3986) and not a forbidden browser scheme.
func (c *Config) Validate() error {
	for _, s := range c.AllowedRedirectSchemes {
		if s == "" || s != strings.ToLower(s) {
			return fmt.Errorf("cimd: AllowedRedirectSchemes entry %q must be a non-empty lowercase scheme", s)
		}
		if _, bad := forbiddenRedirectSchemes[s]; bad {
			return fmt.Errorf("cimd: AllowedRedirectSchemes must not contain %q", s)
		}
		for i, r := range s {
			letter := r >= 'a' && r <= 'z'
			tail := i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')
			if !letter && !tail {
				return fmt.Errorf("cimd: AllowedRedirectSchemes entry %q is not a valid URI scheme", s)
			}
		}
	}
	return nil
}

// audit action names emitted by the Service, as constants so an OTel adapter can map them to attributes.
const (
	AuditFetched         = "cimd.fetched"
	AuditRejectedPolicy  = "cimd.rejected_by_policy"
	AuditDocumentInvalid = "cimd.document_invalid"
)

// Service resolves an https client_id to an in-memory metadata document. New builds it inert, Start
// runs the GC loop and Stop drains it. Every public method is safe from many goroutines. The cache
// is a sync.Map, and GC only deletes keys.
type Service struct {
	cfg     Config
	client  *http.Client
	emitter audit.Emitter

	cache sync.Map // map[string]*cacheEntry, keyed by canonical URL

	// inflight collapses concurrent fetches of the same URL into one
	// outbound request (single-flight).
	inflightMu sync.Mutex
	inflight   map[string]*flight

	mu      sync.Mutex
	started bool
	stopped bool
	stopGC  chan struct{}
	doneGC  chan struct{}
}

// cacheEntry holds one validated document plus the wall-clock time the
// fetch completed. Expiry is computed on read against cfg.CacheTTL.
type cacheEntry struct {
	doc       Document
	fetchedAt time.Time
	// ttl, when non-zero, overrides cfg.CacheTTL for this entry (Cache-Control).
	ttl time.Duration
	// err, when non-nil, marks a negative entry: the fetch failed and the
	// same error is replayed until NegativeCacheTTL elapses.
	err error
}

// flight is one in-progress fetch shared by every concurrent caller.
type flight struct {
	done chan struct{}
	doc  Document
	err  error
}

// NewService builds an inert Service. Start only bounds cache growth over a long-lived process.
// A nil emitter is replaced with audit.NoopEmitter, so a misconfigured deployment never panics on emit.
func NewService(cfg Config, emitter audit.Emitter) *Service {
	if cfg.TrustPolicy == nil {
		cfg.TrustPolicy = DenyAll()
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = DefaultFetchTimeout
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.NegativeCacheTTL == 0 {
		cfg.NegativeCacheTTL = DefaultNegativeCacheTTL
	}
	if cfg.MaxDocumentBytes == 0 {
		cfg.MaxDocumentBytes = DefaultMaxDocumentBytes
	}
	client := cfg.HTTPClient
	if client == nil {
		client = newSafeClient(cfg.FetchTimeout, cfg.AllowPrivateNetworks)
	}
	if emitter == nil {
		emitter = audit.NoopEmitter{}
	}
	return &Service{
		cfg:      cfg,
		client:   client,
		emitter:  emitter,
		inflight: map[string]*flight{},
	}
}

// Start spawns the cache GC goroutine. Idempotent.
func (s *Service) Start() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	s.stopGC = make(chan struct{})
	s.doneGC = make(chan struct{})
	go s.gcLoop(s.stopGC, s.doneGC)
}

// Stop signals the GC goroutine and waits for it to drain. Idempotent.
func (s *Service) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	stop := s.stopGC
	done := s.doneGC
	s.mu.Unlock()
	if stop != nil {
		select {
		case <-stop:
		default:
			close(stop)
		}
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// A timed-out wait can leak one goroutine at worst, and it exits with the process.
		}
	}
}

// gcLoop sweeps expired cache entries.
func (s *Service) gcLoop(stop chan struct{}, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(gcEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.cache.Range(func(k, v any) bool {
				if entry, ok := v.(*cacheEntry); ok {
					if now.Sub(entry.fetchedAt) >= s.entryTTL(entry) {
						s.cache.Delete(k)
					}
				}
				return true
			})
		}
	}
}

// Invalidate drops the cached entry for a single URL. Idempotent; safe
// to call for URLs the Service has never fetched.
func (s *Service) Invalidate(rawURL string) {
	if s == nil {
		return
	}
	s.cache.Delete(cacheKey(rawURL))
	s.sharedDelete(cacheKey(rawURL))
}

// LooksLikeCIMD reports whether a client_id is an absolute https URL with a host, so the AS knows
// to route it through Resolve. TrustPolicy is consulted later, inside Resolve.
func LooksLikeCIMD(clientID string) bool {
	if clientID == "" {
		return false
	}
	if !strings.HasPrefix(clientID, "https://") {
		return false
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	// MCP spec: the client_id URL MUST contain a path component, and the
	// draft forbids dot segments.
	if u.Path == "" || u.Path == "/" {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ErrPolicyDenied is returned when the TrustPolicy rejects the URL.
// Callers map this to invalid_client at the OAuth wire.
var ErrPolicyDenied = errors.New("cimd: trust policy denied URL")

// ErrFetchFailed is returned when the HTTP fetch fails: timeout, TLS
// error, non-2xx status, or oversized body.
var ErrFetchFailed = errors.New("cimd: fetch failed")

// ErrUnsupportedContentType is returned when the response is not application/json. HTML at the same
// URL is refused, so an open redirect cannot be read as a metadata document.
var ErrUnsupportedContentType = errors.New("cimd: unsupported content type")

// Resolve fetches, validates and caches the document at rawURL, and synthesizes an in-memory client
// row that never touches storage. Every failure collapses to invalid_client on the wire, so an
// attacker cannot learn which published URLs exist.
func (s *Service) Resolve(ctx context.Context, rawURL string) (*models.OAuthClient, error) {
	if s == nil {
		return nil, ErrPolicyDenied
	}
	if !LooksLikeCIMD(rawURL) {
		return nil, ErrPolicyDenied
	}
	if !s.cfg.TrustPolicy.Allow(rawURL) {
		s.emitter.EmitAudit(ctx, AuditRejectedPolicy,
			models.TargetRef{Type: "cimd", ID: rawURL},
			map[string]any{"url": rawURL, "reason": "policy_denied"})
		return nil, ErrPolicyDenied
	}
	if s.cfg.DenyHost != nil {
		if u, err := url.Parse(rawURL); err != nil || s.cfg.DenyHost(u.Hostname()) {
			s.emitter.EmitAudit(ctx, AuditRejectedPolicy,
				models.TargetRef{Type: "cimd", ID: rawURL},
				map[string]any{"url": rawURL, "reason": "host_denied"})
			return nil, ErrPolicyDenied
		}
	}
	key := cacheKey(rawURL)
	if cached, ok := s.cache.Load(key); ok {
		if entry, ok := cached.(*cacheEntry); ok {
			if time.Since(entry.fetchedAt) < s.entryTTL(entry) {
				if entry.err != nil {
					return nil, entry.err
				}
				return synthesizeClient(entry.doc), nil
			}
		}
	}
	if doc, ok := s.sharedLoad(ctx, key, rawURL); ok {
		s.cache.Store(key, &cacheEntry{doc: doc, fetchedAt: time.Now()})
		return synthesizeClient(doc), nil
	}
	doc, err := s.fetchOnce(ctx, key, rawURL)
	if err != nil {
		// Already audited inside fetch; no double-emit here.
		return nil, err
	}
	s.sharedStore(ctx, key, doc)
	s.emitter.EmitAudit(ctx, AuditFetched,
		models.TargetRef{Type: "cimd", ID: rawURL},
		map[string]any{
			"url":           rawURL,
			"client_name":   doc.ClientName,
			"redirect_uris": doc.RedirectURIs,
			"grant_types":   doc.GrantTypes,
		})
	return synthesizeClient(doc), nil
}

// entryTTL returns the freshness window for a cache entry.
func (s *Service) entryTTL(e *cacheEntry) time.Duration {
	if e.err != nil {
		return s.cfg.NegativeCacheTTL
	}
	if e.ttl > 0 {
		return e.ttl
	}
	return s.cfg.CacheTTL
}

// fetchOnce lets one fetch per URL run at a time. Followers share the leader's result, and the
// fetch is detached from any single caller's cancellation, so one impatient caller cannot fail the
// rest.
func (s *Service) fetchOnce(ctx context.Context, key, rawURL string) (Document, error) {
	s.inflightMu.Lock()
	if f, ok := s.inflight[key]; ok {
		s.inflightMu.Unlock()
		select {
		case <-f.done:
			return f.doc, f.err
		case <-ctx.Done():
			return Document{}, fmt.Errorf("%w: %v", ErrFetchFailed, ctx.Err())
		}
	}
	f := &flight{done: make(chan struct{})}
	s.inflight[key] = f
	s.inflightMu.Unlock()

	f.doc, f.err = s.fetch(context.WithoutCancel(ctx), rawURL)
	if f.err == nil {
		s.cache.Store(key, &cacheEntry{doc: f.doc, fetchedAt: time.Now(), ttl: f.doc.cacheTTL})
	} else if s.cfg.NegativeCacheTTL > 0 {
		s.cache.Store(key, &cacheEntry{fetchedAt: time.Now(), err: f.err})
	}
	s.inflightMu.Lock()
	delete(s.inflight, key)
	s.inflightMu.Unlock()
	close(f.done)
	return f.doc, f.err
}

// fetch issues the request, enforces the body cap and content-type gate, then validates the bytes.
// Failures are audited as cimd.document_invalid, which separates a bad client from a denied policy.
func (s *Service) fetch(ctx context.Context, rawURL string) (Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		s.auditInvalid(ctx, rawURL, "request_build_failed")
		return Document{}, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "theauth-go/cimd")
	resp, err := s.client.Do(req)
	if err != nil {
		s.auditInvalid(ctx, rawURL, "transport_error")
		return Document{}, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.auditInvalid(ctx, rawURL, fmt.Sprintf("status_%d", resp.StatusCode))
		return Document{}, fmt.Errorf("%w: status %d", ErrFetchFailed, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !isJSONContentType(ct) {
		s.auditInvalid(ctx, rawURL, "content_type_not_json")
		return Document{}, fmt.Errorf("%w: %q", ErrUnsupportedContentType, ct)
	}
	var reader io.Reader = resp.Body
	if s.cfg.MaxDocumentBytes > 0 {
		// LimitReader caps the read; we also peek one byte beyond to
		// detect oversize bodies and reject explicitly.
		reader = io.LimitReader(resp.Body, s.cfg.MaxDocumentBytes+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		s.auditInvalid(ctx, rawURL, "body_read_failed")
		return Document{}, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	if s.cfg.MaxDocumentBytes > 0 && int64(len(body)) > s.cfg.MaxDocumentBytes {
		s.auditInvalid(ctx, rawURL, "body_too_large")
		return Document{}, fmt.Errorf("%w: body exceeds %d bytes", ErrFetchFailed, s.cfg.MaxDocumentBytes)
	}
	doc, err := parseAndValidate(body, rawURL, s.cfg.AllowedRedirectSchemes...)
	if err != nil {
		s.auditInvalid(ctx, rawURL, "document_invalid")
		return Document{}, err
	}
	if s.cfg.HonorCacheControl {
		doc.cacheTTL = s.cacheControlTTL(resp.Header.Get("Cache-Control"))
	}
	return doc, nil
}

// auditInvalid emits the cimd.document_invalid event. Centralized so
// every failure path uses the same shape.
func (s *Service) auditInvalid(ctx context.Context, rawURL, reason string) {
	s.emitter.EmitAudit(ctx, AuditDocumentInvalid,
		models.TargetRef{Type: "cimd", ID: rawURL},
		map[string]any{"url": rawURL, "reason": reason})
}

// isJSONContentType accepts application/json with parameters, such as charset.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	parts := strings.SplitN(ct, ";", 2)
	return strings.EqualFold(strings.TrimSpace(parts[0]), "application/json")
}

// cacheKey canonicalizes the URL for cache lookup so a trailing slash
// or scheme casing variant does not produce a cache miss.
func cacheKey(raw string) string { return canonicalURL(raw) }

// synthesizeClient turns a validated Document into the in-memory client row the AS reads. It never
// touches storage.
func synthesizeClient(doc Document) *models.OAuthClient {
	return &models.OAuthClient{
		ClientID:                doc.ClientID,
		ClientName:              doc.ClientName,
		RedirectURIs:            append([]string(nil), doc.RedirectURIs...),
		GrantTypes:              append([]string(nil), doc.GrantTypes...),
		ResponseTypes:           append([]string(nil), doc.ResponseTypes...),
		Scope:                   doc.Scope,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		JwksURI:                 doc.JwksURI,
		Jwks:                    append([]byte(nil), doc.Jwks...),
		ApplicationType:         doc.ApplicationType,
		Contacts:                append([]string(nil), doc.Contacts...),
		LogoURI:                 doc.LogoURI,
		ClientURI:               doc.ClientURI,
		PolicyURI:               doc.PolicyURI,
		TosURI:                  doc.TosURI,
		SoftwareID:              doc.SoftwareID,
		SoftwareVersion:         doc.SoftwareVersion,
		AnonymousRegistered:     false,
	}
}

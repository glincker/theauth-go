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

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
)

// Default knobs applied when Config zero-values are passed in. The
// values match the conservative defaults documented in the MCP CIMD
// section: small fetch budget, short cache TTL so a publisher's policy
// rotation propagates quickly, hard cap on document size to limit memory
// blow-up from a malicious or buggy host.
const (
	// DefaultFetchTimeout caps one outbound CIMD fetch.
	DefaultFetchTimeout = 5 * time.Second
	// DefaultCacheTTL is how long a validated document stays usable
	// before the next request triggers a re-fetch.
	DefaultCacheTTL = 5 * time.Minute
	// DefaultMaxDocumentBytes caps the size of a CIMD document body.
	// 64 KiB is more than enough for every RFC 7591 metadata document
	// observed in the wild and blocks resource exhaustion via giant
	// responses.
	DefaultMaxDocumentBytes int64 = 64 * 1024
	// gcEvery is how often the cache GC sweep runs. 60s mirrors other
	// in-tree GC loops (webauthn challenges, oauth state).
	gcEvery = time.Minute
)

// Config wires the CIMD service. Mirrors the root theauth.CIMDConfig
// field set the Service actually consumes. All fields are optional;
// missing values fall through to the package defaults.
type Config struct {
	// TrustPolicy decides which https URLs the Service is allowed to
	// fetch. Nil is interpreted as DenyAll (fail-closed); explicit
	// AllowAnyHTTPS or AllowHTTPSHosts is required to enable CIMD in
	// practice.
	TrustPolicy TrustPolicy

	// FetchTimeout caps one outbound HTTP fetch. Zero applies
	// DefaultFetchTimeout.
	FetchTimeout time.Duration

	// CacheTTL caps how long a validated document stays usable before
	// re-fetch. Zero applies DefaultCacheTTL.
	CacheTTL time.Duration

	// MaxDocumentBytes caps the size of a CIMD document body. Zero
	// applies DefaultMaxDocumentBytes; negative disables the cap (not
	// recommended on a public-internet bind).
	MaxDocumentBytes int64

	// HTTPClient is the http.Client used for outbound fetches. Nil
	// constructs a default client honoring FetchTimeout. Tests inject a
	// custom client backed by httptest.NewTLSServer.
	HTTPClient *http.Client
}

// audit action names emitted by the Service. Named constants so the
// future OTel adapter can map them to span attributes without string
// matching the call sites.
const (
	AuditFetched         = "cimd.fetched"
	AuditRejectedPolicy  = "cimd.rejected_by_policy"
	AuditDocumentInvalid = "cimd.document_invalid"
)

// Service resolves an https client_id URL to an in-memory client
// metadata document. Lifecycle mirrors the other internal services: New
// constructs an inert Service, Start spawns the GC loop, Stop drains
// it.
//
// Concurrency: every public method is safe for use from multiple
// goroutines. The cache is a sync.Map; the GC loop only reads (it
// deletes by key, which is safe under sync.Map.Delete).
type Service struct {
	cfg     Config
	client  *http.Client
	emitter audit.Emitter

	cache sync.Map // map[string]*cacheEntry, keyed by canonical URL

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
}

// NewService constructs an inert Service. The Service is safe to call
// before Start because the cache + emitter paths do not depend on the GC
// loop running; Start is only required to keep the cache from growing
// without bound over long-lived processes.
//
// emitter MAY be nil; the Service substitutes audit.NoopEmitter so audit
// emission never panics on a misconfigured deployment.
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
	if cfg.MaxDocumentBytes == 0 {
		cfg.MaxDocumentBytes = DefaultMaxDocumentBytes
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.FetchTimeout}
	}
	if emitter == nil {
		emitter = audit.NoopEmitter{}
	}
	return &Service{
		cfg:     cfg,
		client:  client,
		emitter: emitter,
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
			// Best effort: log via slog would create a cross-package
			// dependency; the worst case is a single leaked goroutine
			// that exits at process exit.
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
					if now.Sub(entry.fetchedAt) >= s.cfg.CacheTTL {
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
}

// LooksLikeCIMD reports whether a client_id string is shaped like a
// CIMD URL. The AS calls this on every authorize / token request to
// decide whether to route through Resolve or through the legacy
// OAuthClientByClientID lookup.
//
// "Shaped like a CIMD URL" means: parses as an absolute URL, scheme is
// "https", host is non-empty. The TrustPolicy is consulted later inside
// Resolve; LooksLikeCIMD only answers "is this a URL at all".
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
	if u.Host == "" {
		return false
	}
	return true
}

// ErrPolicyDenied is returned when the TrustPolicy rejects the URL.
// Callers map this to invalid_client at the OAuth wire.
var ErrPolicyDenied = errors.New("cimd: trust policy denied URL")

// ErrFetchFailed is returned when the HTTP fetch fails: timeout, TLS
// error, non-2xx status, or oversized body.
var ErrFetchFailed = errors.New("cimd: fetch failed")

// ErrUnsupportedContentType is returned when the response Content-Type
// is not application/json. The MCP CIMD spec requires JSON; HTML pages
// served at the same URL are rejected to keep an open-redirect from
// being misinterpreted as a metadata document.
var ErrUnsupportedContentType = errors.New("cimd: unsupported content type")

// Resolve fetches the CIMD document at rawURL, validates it, caches the
// result, and synthesizes an OAuthClient row. The synthesized row never
// touches storage; it lives in the calling request only.
//
// Returns ErrPolicyDenied / ErrFetchFailed / ErrUnsupportedContentType /
// ErrInvalidDocument depending on which gate fired. All errors at the
// OAuth wire collapse to invalid_client per the MCP CIMD section: an AS
// MUST NOT leak whether a published URL exists, returns JSON, fails
// validation, etc., because that exposes the publisher's posture to an
// attacker enumerating client URLs.
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
	key := cacheKey(rawURL)
	now := time.Now()
	if cached, ok := s.cache.Load(key); ok {
		if entry, ok := cached.(*cacheEntry); ok {
			if now.Sub(entry.fetchedAt) < s.cfg.CacheTTL {
				return synthesizeClient(entry.doc), nil
			}
		}
	}
	doc, err := s.fetch(ctx, rawURL)
	if err != nil {
		// Already audited inside fetch; no double-emit here.
		return nil, err
	}
	s.cache.Store(key, &cacheEntry{doc: doc, fetchedAt: now})
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

// fetch issues the HTTP request, enforces the body cap and content-type
// gate, then hands the bytes to parseAndValidate. Network and parse
// failures are audited as cimd.document_invalid so operators can
// distinguish a bad client from a denied policy.
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
		return Document{}, fmt.Errorf("%w: %v", ErrFetchFailed, err)
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
	doc, err := parseAndValidate(body, rawURL)
	if err != nil {
		s.auditInvalid(ctx, rawURL, "document_invalid")
		return Document{}, err
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

// isJSONContentType reports whether ct is an application/json content
// type. Honors the RFC 7231 parameter form ("application/json;
// charset=utf-8") by splitting on ';'.
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

// synthesizeClient lifts a validated Document into the in-memory
// OAuthClient row the AS handlers expect. The synthesized client never
// touches storage (CreatedAt / UpdatedAt are zero, ID is zero); the AS
// authorize + token paths read only the OAuth-relevant fields.
//
// TokenEndpointAuthMethod is preserved as-is. Most CIMD clients are
// public ("none"); confidential CIMD clients are uncommon because the
// metadata document has no place for a secret. The AS still validates
// credentials at /oauth/token via its standard AuthenticateClient path;
// a CIMD-published confidential client with no stored secret will fail
// invalid_client there, which is the correct behavior.
func synthesizeClient(doc Document) *models.OAuthClient {
	return &models.OAuthClient{
		ClientID:                doc.ClientID,
		ClientName:              doc.ClientName,
		RedirectURIs:            append([]string(nil), doc.RedirectURIs...),
		GrantTypes:              append([]string(nil), doc.GrantTypes...),
		ResponseTypes:           append([]string(nil), doc.ResponseTypes...),
		Scope:                   doc.Scope,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		ApplicationType:         doc.ApplicationType,
		Contacts:                append([]string(nil), doc.Contacts...),
		LogoURI:                 doc.LogoURI,
		PolicyURI:               doc.PolicyURI,
		TosURI:                  doc.TosURI,
		SoftwareID:              doc.SoftwareID,
		SoftwareVersion:         doc.SoftwareVersion,
		AnonymousRegistered:     false,
	}
}

package spiffe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Endpoint says where to fetch a trust bundle (SPIFFE Federation bundle endpoint). An https_web
// endpoint is served with a public web PKI certificate, so the default client works. An https_spiffe
// endpoint authenticates with an X.509-SVID and needs a Client that does mutual TLS against your
// bootstrap bundle.
type Endpoint struct {
	// URL must be https.
	URL string
	// Client defaults to a client with Timeout and redirects refused.
	Client *http.Client
	// Timeout defaults to 5s.
	Timeout time.Duration
	// MaxBytes is the largest accepted body, default 1 MiB.
	MaxBytes int64
	// MinRefresh is the fastest polling rate whatever spiffe_refresh_hint says, default 60s.
	MinRefresh time.Duration
	// DefaultRefresh is used when the bundle has no hint, default 5m.
	DefaultRefresh time.Duration
	// MaxStale stops trusting the last good bundle after this long without a refresh, default 24h.
	MaxStale time.Duration
}

// TrustDomainConfig configures one trust domain. At least one of Bundle, Roots or Endpoint is needed.
type TrustDomainConfig struct {
	// Bundle is a bundle document, used first and as the fallback until a refresh succeeds.
	Bundle []byte
	// Roots are PEM root certificates for X.509-SVIDs.
	Roots    [][]byte
	Endpoint *Endpoint
}

const maxRefresh = 24 * time.Hour

type entry struct {
	mu          sync.Mutex
	bundle      *Bundle
	loadedAt    time.Time
	nextAttempt time.Time
	ep          *Endpoint
}

// Store keeps the bundle of each configured trust domain fresh. There is no background goroutine:
// Get refreshes on demand when a bundle is older than its hint. A failed refresh keeps the last good
// bundle until MaxStale, then the domain fails closed.
type Store struct {
	entries map[string]*entry
	now     func() time.Time
}

// NewStore validates the configuration and parses static bundles. now may be nil (time.Now).
func NewStore(domains map[string]TrustDomainConfig, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{entries: map[string]*entry{}, now: now}
	for name, cfg := range domains {
		td, ok := ParseTrustDomain(name)
		if !ok {
			return nil, fmt.Errorf("spiffe: %q is not a valid trust domain name", name)
		}
		if _, dup := s.entries[td]; dup {
			return nil, fmt.Errorf("spiffe: trust domain %q is configured twice", td)
		}
		if cfg.Bundle == nil && len(cfg.Roots) == 0 && cfg.Endpoint == nil {
			return nil, fmt.Errorf("spiffe: trust domain %q needs a bundle, roots or an endpoint", td)
		}
		if cfg.Endpoint != nil && !strings.HasPrefix(strings.ToLower(cfg.Endpoint.URL), "https://") {
			return nil, fmt.Errorf("spiffe: the bundle endpoint of %q must be https", td)
		}
		e := &entry{loadedAt: now(), ep: cfg.Endpoint}
		if cfg.Bundle != nil {
			b, _, err := ParseBundle(td, cfg.Bundle)
			if err != nil {
				return nil, fmt.Errorf("spiffe: trust domain %q: %w", td, err)
			}
			e.bundle = b
		}
		if len(cfg.Roots) > 0 {
			rb, err := BundleFromRoots(td, cfg.Roots...)
			if err != nil {
				return nil, fmt.Errorf("spiffe: trust domain %q: %w", td, err)
			}
			if e.bundle == nil {
				e.bundle = rb
			} else {
				e.bundle.X509Authorities = append(e.bundle.X509Authorities, rb.X509Authorities...)
			}
		}
		s.entries[td] = e
	}
	return s, nil
}

// Get returns the current bundle of a trust domain, or nil when it is unknown, never loaded or stale.
func (s *Store) Get(ctx context.Context, trustDomain string) *Bundle {
	e := s.entries[trustDomain]
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ep != nil && !s.now().Before(e.nextAttempt) {
		_ = s.refreshLocked(ctx, trustDomain, e)
	}
	if e.bundle == nil {
		return nil
	}
	if e.ep != nil && s.now().Sub(e.loadedAt) > orDefault(e.ep.MaxStale, 24*time.Hour) {
		return nil
	}
	return e.bundle
}

// Refresh fetches the bundle now. It returns an error for an unknown domain, a domain without an
// endpoint, a failed fetch, or a bundle whose sequence went backwards.
func (s *Store) Refresh(ctx context.Context, trustDomain string) error {
	e := s.entries[trustDomain]
	if e == nil {
		return errors.New("unknown trust domain")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return s.refreshLocked(ctx, trustDomain, e)
}

func (s *Store) refreshLocked(ctx context.Context, td string, e *entry) error {
	err := s.fetch(ctx, td, e)
	t := s.now()
	if err != nil {
		e.nextAttempt = t.Add(orDefault(e.ep.MinRefresh, time.Minute))
		return err
	}
	e.loadedAt = t
	hint := e.bundle.RefreshHint
	if hint == 0 {
		hint = orDefault(e.ep.DefaultRefresh, 5*time.Minute)
	}
	hint = max(hint, orDefault(e.ep.MinRefresh, time.Minute))
	e.nextAttempt = t.Add(min(hint, maxRefresh))
	return nil
}

func (s *Store) fetch(ctx context.Context, td string, e *entry) error {
	ep := e.ep
	if ep == nil {
		return errors.New("no bundle endpoint configured")
	}
	timeout := orDefault(ep.Timeout, 5*time.Second)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return errors.New("bundle endpoint URL is invalid")
	}
	req.Header.Set("Accept", "application/json")
	client := ep.Client
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("bundle endpoint could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bundle endpoint answered %d", resp.StatusCode)
	}
	limit := ep.MaxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return errors.New("bundle response is too large or unreadable")
	}
	b, _, err := ParseBundle(td, body)
	if err != nil {
		return err
	}
	if cur := e.bundle; cur != nil && cur.HasSequence {
		// Rollback guard: a lower or missing sequence could replay an older authority set.
		if !b.HasSequence || b.Sequence < cur.Sequence {
			return errors.New("bundle sequence went backwards")
		}
	}
	e.bundle = b
	return nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

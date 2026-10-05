package oauth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// ErrProviderUnavailable is returned when a ProviderResolver fails; the flow
// fails closed instead of falling back to another provider.
var ErrProviderUnavailable = errors.New("theauth: provider resolver failed")

// providerNamePattern is the strict shape a name must match before it is
// handed to a ProviderResolver.
var providerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

const maxCachedProviders = 1024

// ValidProviderName reports whether name is safe to pass to a resolver.
func ValidProviderName(name string) bool { return providerNamePattern.MatchString(name) }

// ProviderLookup finds a provider by name for one request.
type ProviderLookup interface {
	Lookup(ctx context.Context, name string) (Provider, bool, error)
}

// ProviderResolver supplies providers that are not known at startup.
type ProviderResolver interface {
	Resolve(ctx context.Context, name string) (Provider, bool, error)
}

// ProviderLister is optionally implemented by a ProviderResolver to
// enumerate its providers.
type ProviderLister interface {
	List(ctx context.Context) ([]Provider, error)
}

type staticLookup map[string]Provider

func (m staticLookup) Lookup(_ context.Context, name string) (Provider, bool, error) {
	p, ok := m[name]
	return p, ok, nil
}

type cacheEntry struct {
	p       Provider
	ok      bool
	expires time.Time
}

// Registry combines the static provider map with an optional resolver and a
// short-lived cache of resolver answers.
type Registry struct {
	static        map[string]Provider
	resolver      ProviderResolver
	resolverFirst bool
	ttl           time.Duration
	now           func() time.Time

	mu    sync.Mutex
	gen   uint64
	cache map[string]cacheEntry
}

// NewRegistry builds a Registry. A ttl of zero or less disables caching.
func NewRegistry(static map[string]Provider, resolver ProviderResolver, resolverFirst bool, ttl time.Duration) *Registry {
	if ttl < 0 {
		ttl = 0
	}
	return &Registry{
		static: static, resolver: resolver, resolverFirst: resolverFirst,
		ttl: ttl, now: time.Now, cache: map[string]cacheEntry{},
	}
}

// Lookup returns the provider for name. A resolver error is returned as
// ErrProviderUnavailable and never falls through to the other source.
func (r *Registry) Lookup(ctx context.Context, name string) (Provider, bool, error) {
	if r.resolver == nil {
		p, ok := r.static[name]
		return p, ok, nil
	}
	if !r.resolverFirst {
		if p, ok := r.static[name]; ok {
			return p, true, nil
		}
	}
	p, ok, err := r.resolve(ctx, name)
	if err != nil || ok {
		return p, ok, err
	}
	if r.resolverFirst {
		p, ok = r.static[name]
		return p, ok, nil
	}
	return nil, false, nil
}

func (r *Registry) resolve(ctx context.Context, name string) (Provider, bool, error) {
	if !ValidProviderName(name) {
		return nil, false, nil
	}
	r.mu.Lock()
	if e, hit := r.cache[name]; hit && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e.p, e.ok, nil
	}
	gen := r.gen
	r.mu.Unlock()

	p, ok, err := r.resolver.Resolve(ctx, name)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	if ok {
		if p == nil || p.Name() != name {
			return nil, false, fmt.Errorf("%w: resolver returned a provider that does not match %q", ErrProviderUnavailable, name)
		}
	} else {
		p = nil
	}
	r.store(name, p, ok, gen)
	return p, ok, nil
}

func (r *Registry) store(name string, p Provider, ok bool, gen uint64) {
	if r.ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if gen != r.gen {
		return
	}
	if len(r.cache) >= maxCachedProviders {
		now := r.now()
		for k, e := range r.cache {
			if !now.Before(e.expires) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxCachedProviders {
			return
		}
	}
	r.cache[name] = cacheEntry{p: p, ok: ok, expires: r.now().Add(r.ttl)}
}

// Invalidate drops the cached answer for name so the next request asks the
// resolver again. An in-flight resolve started before the call is not cached.
func (r *Registry) Invalidate(name string) {
	r.mu.Lock()
	delete(r.cache, name)
	r.gen++
	r.mu.Unlock()
}

// List returns the static providers sorted by name followed by any extra
// providers from a resolver that implements ProviderLister.
func (r *Registry) List(ctx context.Context) ([]Provider, error) {
	names := make([]string, 0, len(r.static))
	for n := range r.static {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Provider, 0, len(names))
	for _, n := range names {
		out = append(out, r.static[n])
	}
	lister, ok := r.resolver.(ProviderLister)
	if !ok {
		return out, nil
	}
	extra, err := lister.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	for _, p := range extra {
		if p == nil {
			continue
		}
		if _, dup := r.static[p.Name()]; dup {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

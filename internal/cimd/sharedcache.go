package cimd

import (
	"context"
	"encoding/json"
	"time"
)

// sharedcache.go: optional second cache tier backed by kv.Cache so several
// replicas reuse one fetched document instead of each hitting the publisher.
// The in-process map stays the first tier. A document read back from the
// shared tier is re-run through parseAndValidate, so a tampered or stale
// entry can never skip validation.

const sharedKeyPrefix = "cimd:doc:"

// sharedLoad returns a validated document from the shared tier, if any.
// Every failure is a miss; the caller falls through to a normal fetch.
func (s *Service) sharedLoad(ctx context.Context, key, rawURL string) (Document, bool) {
	if s.cfg.Cache == nil {
		return Document{}, false
	}
	b, ok, err := s.cfg.Cache.Get(ctx, sharedKeyPrefix+key)
	if err != nil || !ok {
		return Document{}, false
	}
	doc, err := parseAndValidate(b, rawURL)
	if err != nil {
		return Document{}, false
	}
	return doc, true
}

// sharedStore writes a freshly fetched document to the shared tier.
func (s *Service) sharedStore(ctx context.Context, key string, doc Document) {
	if s.cfg.Cache == nil {
		return
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	_ = s.cfg.Cache.Set(ctx, sharedKeyPrefix+key, b, s.cfg.CacheTTL)
}

// sharedDelete drops one URL from the shared tier.
func (s *Service) sharedDelete(key string) {
	if s.cfg.Cache == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.cfg.Cache.Delete(ctx, sharedKeyPrefix+key)
}

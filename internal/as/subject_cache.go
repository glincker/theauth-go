package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/revocation"
)

// maxSubjectActiveCacheTTL caps Config.SubjectActiveCacheTTL, so a misconfiguration cannot delay revocation.
const maxSubjectActiveCacheTTL = 2 * time.Second

// subjectActive is subjectActiveLookup behind a positive-only cache. Only active answers are
// stored, so a negative answer is never sticky.
func (s *Service) subjectActive(ctx context.Context, sub string) bool {
	ttl := s.Cfg.SubjectActiveCacheTTL
	if ttl <= 0 || sub == "" {
		return s.subjectActiveLookup(ctx, sub)
	}
	now := s.Cfg.Clock.Now()
	if v, ok := s.subjectCache.Load(sub); ok {
		if at, ok := v.(time.Time); ok && now.Sub(at) < ttl {
			return true
		}
		s.subjectCache.Delete(sub)
	}
	active := s.subjectActiveLookup(ctx, sub)
	if active {
		s.subjectCache.Store(sub, now)
	}
	return active
}

// InvalidateSubject drops the cached active answer for a token subject, so the next introspection
// reads storage.
func (s *Service) InvalidateSubject(sub string) {
	if s == nil || sub == "" {
		return
	}
	s.subjectCache.Delete(sub)
}

// SubscribeRevocations drops the cached answer for the subject of every agent and owner revocation
// event, so the cache never delays a revocation, even one published by another node.
func (s *Service) SubscribeRevocations(bus revocation.Bus) (func(), error) {
	return bus.Subscribe(func(ev revocation.Event) {
		switch ev.Kind {
		case revocation.Agent:
			s.InvalidateSubject(models.AgentSubjectPrefix + ev.ID)
		case revocation.Owner:
			s.InvalidateSubject(ev.UserID)
		}
	})
}

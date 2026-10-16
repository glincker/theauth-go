package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/revocation"
)

// maxSubjectActiveCacheTTL caps Config.SubjectActiveCacheTTL so a
// misconfiguration cannot turn the cache into a revocation delay.
const maxSubjectActiveCacheTTL = 2 * time.Second

// subjectActive is subjectActiveLookup behind a tiny positive-only cache
// keyed by subject. Only "active" answers are stored, so a negative answer
// is never sticky and a resumed agent or re-enabled user works at once.
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

// InvalidateSubject drops the cached "active" answer for a token subject
// ("agent:<id>" or a user ID) so the next introspection reads storage.
func (s *Service) InvalidateSubject(sub string) {
	if s == nil || sub == "" {
		return
	}
	s.subjectCache.Delete(sub)
}

// SubscribeRevocations drops the cached answer for the subject named by
// every agent and owner revocation event, so the cache never delays a
// revocation, including ones published by another node. It returns the
// unsubscribe func.
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

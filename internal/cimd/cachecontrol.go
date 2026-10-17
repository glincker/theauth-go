package cimd

import (
	"strconv"
	"strings"
	"time"
)

// cachecontrol.go: optional HTTP Cache-Control handling for fetched
// documents (Config.HonorCacheControl).

// cacheControlTTL derives a freshness window from a Cache-Control header. It returns zero when the
// header has no usable directive. The publisher can shorten the window but never extend it past
// cfg.CacheTTL.
func (s *Service) cacheControlTTL(header string) time.Duration {
	if header == "" {
		return 0
	}
	ttl := time.Duration(-1)
	for _, part := range strings.Split(header, ",") {
		d := strings.ToLower(strings.TrimSpace(part))
		switch {
		case d == "no-store" || d == "no-cache":
			ttl = 0
		case strings.HasPrefix(d, "max-age="):
			secs, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64)
			if err != nil || secs < 0 {
				continue
			}
			// no-store / no-cache already pinned ttl to the floor; keep it.
			if ttl != 0 {
				ttl = time.Duration(secs) * time.Second
			}
		}
	}
	if ttl < 0 {
		return 0
	}
	if ttl < MinCacheTTL {
		ttl = MinCacheTTL
	}
	if ttl > s.cfg.CacheTTL {
		ttl = s.cfg.CacheTTL
	}
	return ttl
}

package as

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/delegation"
	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/models"
)

// introspect.go: RFC 7662 token introspection.
//
// Resource servers POST a token here to learn whether it is still active
// and to retrieve the claims required for authorization decisions. The
// endpoint is gated to authenticated clients (the resource server
// registers as an OAuth client and presents its own client_id/secret on
// every call). A successful response carries a Cache-Control: max-age
// header sized from IntrospectionCacheTTL so resource servers can
// de-duplicate within the configured window without losing revocation
// propagation freshness.

// IntrospectionResponse mirrors the JSON shape mandated by RFC 7662
// section 2.2 plus the v2.0 act chain and delegation_grant_id
// forward-compatibility fields (populated only when phase 3 + 4 mints
// token-exchanged access tokens; always absent in this PR).
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	// Act + DelegationGrantID are populated when the token was minted
	// via the RFC 8693 token-exchange grant. Resource servers walk Act
	// inward to outward to render Principal.ActorChain.
	// DelegationGrantID lets audit pipelines correlate every
	// chain-validation failure back to the grant that authorised the
	// original delegation.
	Act               *models.ActorClaim `json:"act,omitempty"`
	DelegationGrantID string             `json:"delegation_grant_id,omitempty"`
	// Cnf is the RFC 7800 confirmation claim. Populated when the token
	// was minted as DPoP-bound (cnf.jkt = base64url SHA-256 thumbprint
	// of the proof key). Resource servers compare this against the
	// thumbprint of the inbound DPoP proof on every protected call.
	Cnf *ConfirmationClaim `json:"cnf,omitempty"`
}

// ConfirmationClaim is the JSON shape of the RFC 7800 cnf claim. Only
// the jkt member is populated today; future confirmation methods (mTLS
// x5t#S256, kid) can land here additively.
type ConfirmationClaim struct {
	JKT string `json:"jkt,omitempty"`
}

// IntrospectToken validates the supplied token and returns the
// structured introspection response. Token type detection: JWTs are
// recognised by the three dot-separated base64 segments; everything
// else is treated as a refresh token (looked up by hash).
//
// Audience binding: when expectedAud is non-empty (resource server
// passes its own identifier), tokens with a mismatching aud return
// active=false. Tokens missing an aud claim are rejected; phase 1 + 2
// mints them with a resource-derived aud unconditionally.
func (s *Service) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (introResp IntrospectionResponse, body []byte, err error) {
	if s == nil {
		return IntrospectionResponse{}, nil, errors.New("theauth: authorization server not configured")
	}
	ctx, span, timer := s.startIntrospectSpan(ctx)
	defer func() { s.finishIntrospectSpan(span, timer, err) }()
	if _, aerr := s.AuthenticateClient(ctx, clientID, clientSecret); aerr != nil {
		err = aerr
		return IntrospectionResponse{}, nil, err
	}
	if token == "" {
		body, _ := json.Marshal(IntrospectionResponse{Active: false})
		return IntrospectionResponse{Active: false}, body, nil
	}
	if cached, ok := s.introspectCacheGet(token, expectedAud); ok {
		var resp IntrospectionResponse
		_ = json.Unmarshal(cached, &resp)
		// Even on cache hit we re-verify the actor chain (and delegation
		// grant) so revocation propagation honors the
		// IntrospectionCacheTTL upper bound but never lags behind a
		// resume / revoke decision the operator made AFTER the cache
		// was populated. Inactive chain entries flip active=false and
		// bypass the cache body entirely.
		if resp.Active && (resp.Act != nil || resp.DelegationGrantID != "") {
			if !s.chainStillActive(ctx, &resp) {
				resp = IntrospectionResponse{Active: false}
				body, _ := json.Marshal(resp)
				return resp, body, nil
			}
		}
		return resp, cached, nil
	}
	// Heuristic: a JWT has three dot-separated segments. Refresh tokens
	// are base64url single segments.
	if strings.Count(token, ".") == 2 {
		resp := s.introspectJWT(ctx, token, expectedAud)
		body, _ = json.Marshal(resp)
		s.introspectCacheSet(token, expectedAud, body)
		return resp, body, nil
	}
	resp := s.introspectRefreshToken(ctx, token)
	body, _ = json.Marshal(resp)
	s.introspectCacheSet(token, expectedAud, body)
	return resp, body, nil
}

func (s *Service) introspectJWT(ctx context.Context, token, expectedAud string) IntrospectionResponse {
	claims, err := jwt.Verify(token, s.PublicKeyByKID, expectedAud, time.Now())
	if err != nil {
		return IntrospectionResponse{Active: false}
	}
	// Audience binding is mandatory: tokens without an aud claim are
	// rejected.
	if claims.Aud == "" {
		return IntrospectionResponse{Active: false}
	}
	resp := IntrospectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		TokenType: "Bearer",
		Exp:       claims.Exp,
		Iat:       claims.Iat,
		Sub:       claims.Sub,
		Aud:       claims.Aud,
		Iss:       claims.Iss,
		Jti:       claims.Jti,
	}
	// Populate the act chain and delegation_grant_id from the JWT
	// Extras so the cached body carries them and a downstream resource
	// server can render the Principal.ActorChain without a second AS
	// call.
	if raw, ok := claims.Extra["act"]; ok && raw != nil {
		resp.Act = actorClaimFromAny(raw)
	}
	if v, ok := claims.Extra["delegation_grant_id"]; ok {
		if sval, ok := v.(string); ok {
			resp.DelegationGrantID = sval
		}
	}
	if v, ok := claims.Extra["cnf"]; ok {
		if m, ok := v.(map[string]any); ok {
			if jkt, ok := m["jkt"].(string); ok && jkt != "" {
				resp.Cnf = &ConfirmationClaim{JKT: jkt}
			}
		}
	}
	// Walk the chain on every fresh introspection: any actor in the
	// chain being suspended/revoked, or the delegation grant being
	// revoked, flips active=false immediately. Cache hits perform the
	// same check on the cached body so revocations are observable
	// within IntrospectionCacheTTL of the operator decision (or
	// sooner).
	if resp.Act != nil || resp.DelegationGrantID != "" {
		if !s.chainStillActive(ctx, &resp) {
			return IntrospectionResponse{Active: false}
		}
	}
	// Walk the sub: if it names an agent ("agent:<id>"), reject when
	// that agent is no longer active. This catches the agent-self-token
	// path (client_credentials grant) without touching the chain checks
	// above.
	if strings.HasPrefix(resp.Sub, models.AgentSubjectPrefix) {
		ag, err := s.lookupAgent(ctx, resp.Sub)
		if err != nil || ag == nil || ag.Status != models.AgentStatusActive {
			return IntrospectionResponse{Active: false}
		}
	}
	return resp
}

// chainStillActive walks the full actor chain (innermost-first) and
// verifies every agent referenced is currently active, plus the
// delegation grant (when present) is not revoked. Returns false if
// anything is off; caller flips active=false.
//
// Perf re-audit 2026-06-21 (item 3): when a token has an act chain but
// NO delegation grant, the agent-walk result is cached in chainCache
// keyed by the outermost agent ID for up to chainCacheTTL (5s). Callers
// that suspend or revoke an agent MUST call InvalidateChainCache so the
// next walk sees the fresh status without waiting for the TTL to expire.
//
// Tokens with a DelegationGrantID skip the cache because grant revocations
// do not flow through the agent service; they are therefore always
// re-checked against storage.
func (s *Service) chainStillActive(ctx context.Context, resp *IntrospectionResponse) bool {
	if s == nil {
		return true
	}
	now := s.Cfg.Clock.Now()

	// Grant check is never cached: revocations must propagate immediately.
	if resp.DelegationGrantID != "" {
		var id models.ULID
		if err := id.UnmarshalText([]byte(resp.DelegationGrantID)); err == nil {
			g, err := s.Storage.DelegationGrantByID(ctx, id)
			if err != nil {
				return false
			}
			if !delegation.Active(g, now) {
				return false
			}
		}
	}

	// Agent-chain walk: cache only when there is no delegation grant, so
	// the cache key (outermost act.sub) uniquely identifies the chain
	// state without needing to track grant invalidations. When a grant ID
	// is present the grant check above already ran; fall through to the
	// agent walk without caching.
	cacheKey := ""
	if resp.Act != nil && resp.DelegationGrantID == "" {
		cacheKey = resp.Act.Sub
	}
	if cacheKey != "" {
		if v, ok := s.chainCache.Load(cacheKey); ok {
			if entry, ok := v.(*chainCacheEntry); ok {
				if s.Cfg.Clock.Now().Sub(entry.checkedAt) < chainCacheTTL {
					return entry.active
				}
				// Stale: fall through to re-walk.
				s.chainCache.Delete(cacheKey)
			}
		}
	}

	active := true
	for cur := resp.Act; cur != nil; cur = cur.Act {
		ag, err := s.lookupAgent(ctx, cur.Sub)
		if err != nil || ag == nil {
			active = false
			break
		}
		if ag.Status != models.AgentStatusActive {
			active = false
			break
		}
	}

	if cacheKey != "" {
		s.chainCache.Store(cacheKey, &chainCacheEntry{
			active:    active,
			checkedAt: s.Cfg.Clock.Now(),
		})
	}
	return active
}

// lookupAgent resolves an "agent:<id>" subject claim through the
// AgentLookup callback. When the callback is unset (no agent identity
// service configured) returns (nil, nil) so the chain check falls
// through to "no agent metadata to verify" and the JWT signature path
// remains the sole source of truth.
func (s *Service) lookupAgent(ctx context.Context, sub string) (*models.Agent, error) {
	if s.AgentLookup == nil {
		return nil, nil
	}
	return s.AgentLookup.AgentBySubjectClaim(ctx, sub)
}

// actorClaimFromAny converts the {sub, act?} map shape into an
// *ActorClaim pointer. Mirrors actorFromAny in token_v34.go but returns
// the public ActorClaim type so the introspection response can
// serialize it.
func actorClaimFromAny(raw any) *models.ActorClaim {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	sub, _ := m["sub"].(string)
	if sub == "" {
		return nil
	}
	out := &models.ActorClaim{Sub: sub}
	if inner, ok := m["act"]; ok {
		out.Act = actorClaimFromAny(inner)
	}
	return out
}

func (s *Service) introspectRefreshToken(ctx context.Context, token string) IntrospectionResponse {
	hash := crypto.HashToken(token)
	rt, err := s.Storage.RefreshTokenByHash(ctx, hash)
	if err != nil {
		return IntrospectionResponse{Active: false}
	}
	if rt.RevokedAt != nil || !rt.ExpiresAt.After(time.Now()) {
		return IntrospectionResponse{Active: false}
	}
	sub := ""
	if rt.UserID != nil {
		sub = rt.UserID.String()
	}
	return IntrospectionResponse{
		Active:    true,
		Scope:     scopeJoin(rt.Scope),
		ClientID:  rt.ClientID,
		TokenType: "refresh_token",
		Exp:       rt.ExpiresAt.Unix(),
		Iat:       rt.IssuedAt.Unix(),
		Sub:       sub,
		Aud:       rt.Resource,
		Iss:       s.Cfg.Issuer,
	}
}

// introspectCacheGet returns the cached body for a (token, aud) pair or
// false when missing/expired. Cache entries are keyed by sha256 of the
// token plus the expected aud so different resource servers do not
// pollute each other.
func (s *Service) introspectCacheGet(token, aud string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	key := introspectCacheKey(token, aud)
	v, ok := s.introspectCache.Load(key)
	if !ok {
		return nil, false
	}
	entry, ok := v.(*introspectCacheEntry)
	if !ok || entry == nil {
		return nil, false
	}
	if s.Cfg.Clock.Now().After(entry.expiresAt) {
		s.introspectCache.Delete(key)
		return nil, false
	}
	return entry.body, true
}

func (s *Service) introspectCacheSet(token, aud string, body []byte) {
	if s == nil {
		return
	}
	s.introspectCache.Store(introspectCacheKey(token, aud), &introspectCacheEntry{
		expiresAt: s.Cfg.Clock.Now().Add(s.Cfg.IntrospectionCacheTTL),
		body:      body,
	})
}

func introspectCacheKey(token, aud string) string {
	hash := crypto.HashToken(token)
	// hex-encode to keep the key printable; aud is appended separated by
	// '\x00' so an audience containing a colon does not collide.
	const hex = "0123456789abcdef"
	out := make([]byte, len(hash)*2+1+len(aud))
	for i, b := range hash {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	out[len(hash)*2] = 0
	copy(out[len(hash)*2+1:], aud)
	return string(out)
}

// delegationActive + narrowDelegatedScope previously lived here as
// duplicates of the root service_delegation.go helpers. PR C of the
// 2026-06 architecture reorg consolidated both into
// internal/delegation; this file now imports delegation.Active and
// delegation.NarrowScope so the helpers exist in exactly one place.

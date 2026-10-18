package as

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/delegation"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// Resource servers POST a token here to learn whether it is active and which claims apply. The
// endpoint requires an authenticated client. Responses carry Cache-Control sized from
// IntrospectionCacheTTL.

// IntrospectionResponse is the RFC 7662 section 2.2 response, plus the act chain and
// delegation_grant_id fields.
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
	// Act and DelegationGrantID are set for RFC 8693 token-exchange tokens. Resource servers walk Act
	// to render the chain.
	Act               *models.ActorClaim `json:"act,omitempty"`
	DelegationGrantID string             `json:"delegation_grant_id,omitempty"`
	// Cnf is the RFC 7800 confirmation claim, set for DPoP-bound tokens (cnf.jkt is the proof key thumbprint).
	Cnf *ConfirmationClaim `json:"cnf,omitempty"`
	// AuthorizationDetails carries the RFC 9396 details the token was granted, when it has any.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
	// AuthTime, ACR and AMR report the user authentication context the
	// token was issued under (OIDC Core, RFC 9470), when it has one.
	AuthTime int64    `json:"auth_time,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// DeviceID is set on tokens issued to a registered device. Introspection
	// reports the token inactive once the device is revoked.
	DeviceID string `json:"device_id,omitempty"`
}

// ConfirmationClaim is the JSON shape of the RFC 7800 cnf claim. Only jkt is populated today.
type ConfirmationClaim struct {
	JKT string `json:"jkt,omitempty"`
}

// IntrospectToken validates a token and returns its introspection response. JWTs are recognised by
// their three segments; anything else is a refresh token looked up by hash. A non-empty expectedAud
// makes mismatched audiences inactive.
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
		// Cache hits re-verify the actor chain and delegation grant, so revocations land within
		// IntrospectionCacheTTL and never lag an operator decision. Inactive chain entries bypass the
		// cache.
		if resp.Active && resp.Jti != "" && s.accessJTIRevoked(ctx, resp.Jti) {
			resp = IntrospectionResponse{Active: false}
			body, _ := json.Marshal(resp)
			return resp, body, nil
		}
		if resp.Active && resp.DeviceID != "" && !s.deviceActive(ctx, resp.DeviceID) {
			resp = IntrospectionResponse{Active: false}
			body, _ := json.Marshal(resp)
			return resp, body, nil
		}
		if resp.Active && (resp.Act != nil || resp.DelegationGrantID != "") {
			if !s.chainStillActive(ctx, &resp) {
				resp = IntrospectionResponse{Active: false}
				body, _ := json.Marshal(resp)
				return resp, body, nil
			}
		}
		// Agent self tokens and user tokens carry no act chain, so they re-check subject state on every
		// call rather than riding the cache after a suspend or disable.
		if resp.Active && !s.subjectActive(ctx, resp.Sub) {
			resp = IntrospectionResponse{Active: false}
			body, _ := json.Marshal(resp)
			return resp, body, nil
		}
		return resp, cached, nil
	}
	// A JWT has three dot-separated segments. Refresh tokens are single base64url segments.
	if strings.Count(token, ".") == 2 {
		resp := s.introspectJWT(ctx, token, expectedAud)
		body, _ = json.Marshal(resp)
		s.introspectCacheSet(token, expectedAud, body)
		return resp, body, nil
	}
	if opaque, ok := s.introspectOpaque(ctx, token, expectedAud); ok {
		body, _ = json.Marshal(opaque)
		s.introspectCacheSet(token, expectedAud, body)
		return opaque, body, nil
	}
	resp := s.introspectRefreshToken(ctx, token)
	body, _ = json.Marshal(resp)
	s.introspectCacheSet(token, expectedAud, body)
	return resp, body, nil
}

func (s *Service) introspectJWT(ctx context.Context, token, expectedAud string) IntrospectionResponse {
	claims, err := s.verifyAccessJWT(token, expectedAud, time.Now())
	if err != nil {
		return IntrospectionResponse{Active: false}
	}
	return s.introspectClaims(ctx, claims)
}

// introspectOpaque answers for a reference access token.
func (s *Service) introspectOpaque(ctx context.Context, token, expectedAud string) (IntrospectionResponse, bool) {
	claims, ok := s.lookupOpaqueClaims(ctx, token)
	if !ok {
		return IntrospectionResponse{}, false
	}
	if expectedAud != "" && claims.Aud != expectedAud {
		return IntrospectionResponse{Active: false}, true
	}
	return s.introspectClaims(ctx, claims), true
}

// introspectClaims turns a verified access token claim set into the RFC 7662 response, applying the
// denylist and actor chain checks. JWT and opaque tokens share it so both answer identically.
func (s *Service) introspectClaims(ctx context.Context, claims jwt.Claims) IntrospectionResponse {
	// Audience binding is mandatory: tokens without an aud claim are rejected.
	if claims.Aud == "" {
		return IntrospectionResponse{Active: false}
	}
	if s.accessJTIRevoked(ctx, claims.Jti) {
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

		AuthorizationDetails: authorizationDetailsRaw(claims.Extra),
	}
	if raw, ok := claims.Extra["act"]; ok && raw != nil {
		resp.Act = actorClaimFromAny(raw)
	}
	if v, ok := claims.Extra["delegation_grant_id"]; ok {
		if sval, ok := v.(string); ok {
			resp.DelegationGrantID = sval
		}
	}
	resp.AuthTime, resp.ACR, resp.AMR = authContextFromExtra(claims.Extra)
	if v, ok := claims.Extra["cnf"]; ok {
		if m, ok := v.(map[string]any); ok {
			if jkt, ok := m["jkt"].(string); ok && jkt != "" {
				resp.Cnf = &ConfirmationClaim{JKT: jkt}
				resp.TokenType = "DPoP"
			}
		}
	}
	if id, ok := claims.Extra["device_id"].(string); ok && id != "" {
		resp.DeviceID = id
		if !s.deviceActive(ctx, id) {
			return IntrospectionResponse{Active: false}
		}
	}
	// Every fresh introspection walks the chain: a suspended or revoked actor, or a revoked grant,
	// makes the token inactive.
	if resp.Act != nil || resp.DelegationGrantID != "" {
		if !s.chainStillActive(ctx, &resp) {
			return IntrospectionResponse{Active: false}
		}
	}
	// An agent subject must still be active. This covers agent self tokens that carry no act chain.
	if !s.subjectActive(ctx, resp.Sub) {
		return IntrospectionResponse{Active: false}
	}
	return resp
}

// accountStateReader is the optional user store capability that reports a user's disabled flag.
type accountStateReader interface {
	AccountStateByUserID(ctx context.Context, userID models.ULID) (models.AccountState, error)
}

// subjectActiveLookup reports whether the token subject may still act. Agent subjects must be
// active and user subjects must not be disabled; other subjects pass. Lookup failures other than
// not-found fail closed.
func (s *Service) subjectActiveLookup(ctx context.Context, sub string) bool {
	if strings.HasPrefix(sub, models.AgentSubjectPrefix) {
		ag, err := s.lookupAgent(ctx, sub)
		return err == nil && agentLive(ag, s.Cfg.Clock.Now())
	}
	if s.Users == nil || sub == "" {
		return true
	}
	rd, ok := s.Users.(accountStateReader)
	if !ok {
		return true
	}
	var uid models.ULID
	if err := uid.UnmarshalText([]byte(sub)); err != nil {
		return true
	}
	st, err := rd.AccountStateByUserID(ctx, uid)
	if err != nil {
		return errors.Is(err, models.ErrStorageNotFound)
	}
	return st.DisabledAt == nil
}

// chainStillActive walks the actor chain and checks that each agent is active and the delegation
// grant is not revoked. Chain results without a grant are cached for chainCacheTTL, so callers that
// suspend or revoke an agent must call InvalidateChainCache. Tokens with a grant are never cached,
// because grant revocations skip the agent service.
func (s *Service) chainStillActive(ctx context.Context, resp *IntrospectionResponse) bool {
	if s == nil {
		return true
	}
	now := s.Cfg.Clock.Now()

	// Grant checks are never cached: revocations must propagate immediately.
	if resp.DelegationGrantID != "" {
		var id models.ULID
		if err := id.UnmarshalText([]byte(resp.DelegationGrantID)); err != nil {
			return false
		}
		g, err := s.Storage.DelegationGrantByID(ctx, id)
		if err != nil {
			return false
		}
		if !delegation.Active(g, now) {
			return false
		}
	}

	cacheKey := ""
	if resp.Act != nil && resp.DelegationGrantID == "" {
		cacheKey = resp.Act.Sub
	}
	if cacheKey != "" {
		if v, ok := s.chainCache.Load(cacheKey); ok {
			if entry, ok := v.(*chainCacheEntry); ok {
				// A cached active answer must not outlive the earliest agent expiry in the chain.
				fresh := now.Sub(entry.checkedAt) < chainCacheTTL && (entry.expiresAt.IsZero() || now.Before(entry.expiresAt))
				if fresh {
					return entry.active
				}
				s.chainCache.Delete(cacheKey)
			}
		}
	}

	active := true
	var earliestExp time.Time
	for cur := resp.Act; cur != nil; cur = cur.Act {
		ag, err := s.lookupAgent(ctx, cur.Sub)
		if err != nil || ag == nil {
			active = false
			break
		}
		if !agentLive(ag, now) {
			active = false
			break
		}
		earliestExp = capExpiry(earliestExp, agentExpiryBound(ag))
	}

	if cacheKey != "" {
		s.chainCache.Store(cacheKey, &chainCacheEntry{
			active:    active,
			checkedAt: now,
			expiresAt: earliestExp,
		})
	}
	return active
}

// lookupAgent resolves an "agent:<id>" subject through the AgentLookup callback. Without the
// callback the chain check has no agent metadata to verify, and the JWT signature stays the only
// source of truth.
func (s *Service) lookupAgent(ctx context.Context, sub string) (*models.Agent, error) {
	if s.AgentLookup == nil {
		return nil, nil
	}
	return s.AgentLookup.AgentBySubjectClaim(ctx, sub)
}

// actorClaimFromAny converts the {sub, act} map shape into the public ActorClaim type.
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

// introspectCacheGet returns the cached body for a (token, aud) pair, or false when missing or
// expired. Keys are sha256 digests, so different resource servers never share an entry.
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

// purgeIntrospectCache drops every cached body so a revocation is visible immediately on this instance.
func (s *Service) purgeIntrospectCache() {
	if s == nil {
		return
	}
	s.introspectCache.Range(func(k, _ any) bool {
		s.introspectCache.Delete(k)
		return true
	})
}

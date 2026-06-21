package theauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/jwt"
)

// service_introspect.go: RFC 7662 token introspection.
//
// Resource servers POST a token here to learn whether it is still active and
// to retrieve the claims required for authorization decisions. The endpoint
// is gated to authenticated clients (the resource server registers as an
// OAuth client and presents its own client_id/secret on every call). A
// successful response carries a Cache-Control: max-age header sized from
// IntrospectionCacheTTL so resource servers can de-duplicate within the
// configured window without losing revocation propagation freshness.

// IntrospectionResponse mirrors the JSON shape mandated by RFC 7662
// section 2.2 plus the v2.0 act chain and delegation_grant_id forward-
// compatibility fields (populated only when phase 3 + 4 mints token-exchanged
// access tokens; always absent in this PR).
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
	// Act + DelegationGrantID are populated when the token was minted via
	// the RFC 8693 token-exchange grant. Resource servers walk Act inward
	// to outward to render Principal.ActorChain. DelegationGrantID lets
	// audit pipelines correlate every chain-validation failure back to the
	// grant that authorised the original delegation.
	Act               *ActorClaim `json:"act,omitempty"`
	DelegationGrantID string      `json:"delegation_grant_id,omitempty"`
}

// IntrospectToken validates the supplied token and returns the structured
// introspection response. Token type detection: JWTs are recognised by the
// three dot-separated base64 segments; everything else is treated as a
// refresh token (looked up by hash).
//
// Audience binding: when expectedAud is non-empty (resource server passes
// its own identifier), tokens with a mismatching aud return active=false.
// Tokens missing an aud claim are rejected; phase 1 + 2 mints them with a
// resource-derived aud unconditionally.
func (a *TheAuth) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (IntrospectionResponse, []byte, error) {
	if a.as == nil {
		return IntrospectionResponse{}, nil, errors.New("theauth: authorization server not configured")
	}
	if _, err := a.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return IntrospectionResponse{}, nil, err
	}
	if token == "" {
		body, _ := json.Marshal(IntrospectionResponse{Active: false})
		return IntrospectionResponse{Active: false}, body, nil
	}
	if cached, ok := a.introspectCacheGet(token, expectedAud); ok {
		var resp IntrospectionResponse
		_ = json.Unmarshal(cached, &resp)
		// Even on cache hit we re-verify the actor chain (and delegation
		// grant) so revocation propagation honors the
		// IntrospectionCacheTTL upper bound but never lags behind a
		// resume / revoke decision the operator made AFTER the cache was
		// populated. Inactive chain entries flip active=false and bypass
		// the cache body entirely.
		if resp.Active && (resp.Act != nil || resp.DelegationGrantID != "") {
			if !a.chainStillActive(ctx, &resp) {
				resp = IntrospectionResponse{Active: false}
				body, _ := json.Marshal(resp)
				return resp, body, nil
			}
		}
		return resp, cached, nil
	}
	// Heuristic: a JWT has three dot-separated segments. Refresh tokens are
	// base64url single segments.
	if strings.Count(token, ".") == 2 {
		resp := a.introspectJWT(ctx, token, expectedAud)
		body, _ := json.Marshal(resp)
		a.introspectCacheSet(token, expectedAud, body)
		return resp, body, nil
	}
	resp := a.introspectRefreshToken(ctx, token)
	body, _ := json.Marshal(resp)
	a.introspectCacheSet(token, expectedAud, body)
	return resp, body, nil
}

func (a *TheAuth) introspectJWT(ctx context.Context, token, expectedAud string) IntrospectionResponse {
	claims, err := jwt.Verify(token, a.publicKeyByKID, expectedAud, time.Now())
	if err != nil {
		return IntrospectionResponse{Active: false}
	}
	// Audience binding is mandatory: tokens without an aud claim are rejected.
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
	// Populate the act chain and delegation_grant_id from the JWT Extras
	// so the cached body carries them and a downstream resource server can
	// render the Principal.ActorChain without a second AS call.
	if raw, ok := claims.Extra["act"]; ok && raw != nil {
		resp.Act = actorClaimFromAny(raw)
	}
	if v, ok := claims.Extra["delegation_grant_id"]; ok {
		if s, ok := v.(string); ok {
			resp.DelegationGrantID = s
		}
	}
	// Walk the chain on every fresh introspection: any actor in the chain
	// being suspended/revoked, or the delegation grant being revoked,
	// flips active=false immediately. Cache hits perform the same check on
	// the cached body so revocations are observable within
	// IntrospectionCacheTTL of the operator decision (or sooner).
	if resp.Act != nil || resp.DelegationGrantID != "" {
		if !a.chainStillActive(ctx, &resp) {
			return IntrospectionResponse{Active: false}
		}
	}
	// Walk the sub: if it names an agent ("agent:<id>"), reject when that
	// agent is no longer active. This catches the agent-self-token path
	// (client_credentials grant) without touching the chain checks above.
	if strings.HasPrefix(resp.Sub, AgentSubjectPrefix) {
		ag, err := a.agentBySubjectClaim(ctx, resp.Sub)
		if err != nil || ag == nil || ag.Status != AgentStatusActive {
			return IntrospectionResponse{Active: false}
		}
	}
	return resp
}

// chainStillActive walks the full actor chain (innermost-first) and verifies
// every agent referenced is currently active, plus the delegation grant
// (when present) is not revoked. Returns false if anything is off; caller
// flips active=false. Background context shielding is unnecessary because
// the introspection call itself is request-scoped.
func (a *TheAuth) chainStillActive(ctx context.Context, resp *IntrospectionResponse) bool {
	if a.as == nil {
		return true
	}
	now := time.Now()
	if resp.DelegationGrantID != "" {
		var id ULID
		if err := id.UnmarshalText([]byte(resp.DelegationGrantID)); err == nil {
			g, err := a.as.storage.DelegationGrantByID(ctx, id)
			if err != nil {
				return false
			}
			if !delegationActive(g, now) {
				return false
			}
		}
	}
	for cur := resp.Act; cur != nil; cur = cur.Act {
		ag, err := a.agentBySubjectClaim(ctx, cur.Sub)
		if err != nil || ag == nil {
			return false
		}
		if ag.Status != AgentStatusActive {
			return false
		}
	}
	return true
}

// actorClaimFromAny converts the {sub, act?} map shape into an *ActorClaim
// pointer. Mirrors actorFromAny in service_token_v34.go but returns the
// public ActorClaim type so the introspection response can serialize it.
func actorClaimFromAny(raw any) *ActorClaim {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	sub, _ := m["sub"].(string)
	if sub == "" {
		return nil
	}
	out := &ActorClaim{Sub: sub}
	if inner, ok := m["act"]; ok {
		out.Act = actorClaimFromAny(inner)
	}
	return out
}

func (a *TheAuth) introspectRefreshToken(ctx context.Context, token string) IntrospectionResponse {
	hash := crypto.HashToken(token)
	rt, err := a.as.storage.RefreshTokenByHash(ctx, hash)
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
		Iss:       a.as.cfg.Issuer,
	}
}

// introspectCacheGet returns the cached body for a (token, aud) pair or false
// when missing/expired. Cache entries are keyed by sha256 of the token plus
// the expected aud so different resource servers do not pollute each other.
func (a *TheAuth) introspectCacheGet(token, aud string) ([]byte, bool) {
	if a.as == nil {
		return nil, false
	}
	key := introspectCacheKey(token, aud)
	v, ok := a.as.introspectCache.Load(key)
	if !ok {
		return nil, false
	}
	entry, ok := v.(*introspectCacheEntry)
	if !ok || entry == nil {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		a.as.introspectCache.Delete(key)
		return nil, false
	}
	return entry.body, true
}

func (a *TheAuth) introspectCacheSet(token, aud string, body []byte) {
	if a.as == nil {
		return
	}
	a.as.introspectCache.Store(introspectCacheKey(token, aud), &introspectCacheEntry{
		expiresAt: time.Now().Add(a.as.cfg.IntrospectionCacheTTL),
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

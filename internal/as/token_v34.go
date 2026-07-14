package as

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/chain"
	"github.com/glincker/theauth-go/internal/delegation"
	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// token_v34.go: v2.0 phase 3 + 4 grants. Adds the OAuth 2.0
// client_credentials grant (phase 3) and the RFC 8693 token-exchange
// grant (phase 4) to the existing /oauth/token multiplexer.

// TokenExchangeRequest is the parsed form-encoded body of a
// token-exchange call. Field names map 1:1 onto the RFC 8693 wire form.
type TokenExchangeRequest struct {
	ClientID           string
	ClientSecret       string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	RequestedTokenType string
	Resource           string
	Audience           string
	Scope              []string
}

// ClientCredentialsToken mints a self-token for the authenticated agent
// client. The token's sub is "agent:<id>"; aud is bound to the resource
// parameter (RFC 8707); scope is intersected with both the agent's
// registered scope set and the resource catalog. Suspended / revoked
// agents fail with ErrAgentInactive (mapped to access_denied at the
// wire).
//
// Audit emission: agent.token_minted on success.
func (s *Service) ClientCredentialsToken(ctx context.Context, req TokenRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if s.AgentPolicy == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	ctx, span, timer := s.startTokenSpan(ctx, "client_credentials")
	defer func() { s.finishTokenSpan(span, timer, "client_credentials", err) }()
	var client *models.OAuthClient
	client, err = s.AuthenticateClientFromRequest(ctx, req, s.tokenEndpointURL())
	if err != nil {
		return TokenResponse{}, err
	}
	agent, err := s.Storage.AgentByClientID(ctx, client.ClientID)
	if err != nil {
		return TokenResponse{}, models.ErrOAuthInvalidClient
	}
	if agent.Status != models.AgentStatusActive {
		return TokenResponse{}, models.ErrAgentInactive
	}
	if req.Resource == "" {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	resource, ok := s.ResourceByIdentifier(req.Resource)
	if !ok {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	// Scope narrowing: request must be a subset of the agent's
	// permitted scope set AND the resource catalog. Empty request means
	// "issue the intersection".
	registered := scopeSplit(client.Scope)
	if len(registered) == 0 {
		registered = agent.Scope
	}
	available := chain.ScopeIntersect(registered, resource.Scopes)
	requested := req.Scope
	if len(requested) == 0 {
		requested = available
	} else if !chain.ScopeSubset(requested, available) {
		return TokenResponse{}, models.ErrOAuthInvalidScope
	}
	if len(requested) == 0 {
		return TokenResponse{}, models.ErrOAuthInvalidScope
	}
	now := time.Now().UTC()
	jti := ulid.New().String()
	signingKey, priv, err := s.CurrentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	claims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      models.AgentSubjectPrefix + agent.ID.String(),
		Aud:      req.Resource,
		Exp:      now.Add(s.Cfg.AccessTokenTTL).Unix(),
		Iat:      now.Unix(),
		Jti:      jti,
		ClientID: client.ClientID,
		Scope:    scopeJoin(requested),
		Typ:      jwt.TypeAccessToken,
		Extra: map[string]any{
			"agent": map[string]any{
				"id":              agent.ID.String(),
				"owner_user_id":   ptrToString(agent.OwnerUserID),
				"organization_id": ptrToString(agent.OrganizationID),
			},
		},
	}
	if err := s.applyOnTokenIssued(ctx, &claims); err != nil {
		return TokenResponse{}, err
	}
	access, err := jwt.Sign(claims, signingKey.KID, priv)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign agent token: %w", err)
	}
	_ = s.Storage.UpdateAgentLastActive(ctx, agent.ID, now)
	s.Audit.EmitAudit(ctx, "agent.token_minted", models.TargetRef{Type: "agent", ID: agent.ID.String()}, map[string]any{
		"agent_id":  agent.ID.String(),
		"client_id": client.ClientID,
		"jti":       jti,
		"resource":  req.Resource,
		"scope":     requested,
		"grant":     models.GrantTypeClientCredentials,
	})
	return TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.Cfg.AccessTokenTTL.Seconds()),
		Scope:       scopeJoin(requested),
	}, nil
}

// ExchangeToken implements RFC 8693 token exchange. The authenticated
// client (an agent's OAuth client) presents:
//   - subject_token: a JWT issued by this AS naming the principal the
//     mint is acting on behalf of. The principal may be a user or
//     another agent (sub-delegation). Required.
//   - actor_token: the agent's own self-token (issued via the
//     client_credentials grant). Optional but recommended; when present
//     its sub MUST match "agent:<id>" of the authenticated client.
//   - resource: the RFC 8707 binding. MUST match the subject token's aud.
//   - scope: optional narrowing. Default to the intersection of
//     (subject_scope, delegation.scope_grant).
//
// The eleven step validation in spec section 7 is enforced; see the
// individual sub-helpers below.
func (s *Service) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if s.AgentPolicy == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	ctx, span, timer := s.startTokenSpan(ctx, "token-exchange")
	defer func() { s.finishTokenSpan(span, timer, "token-exchange", err) }()
	// Step 1: authenticate the requesting client (the agent).
	// Token exchange does not use JWT client assertions in the current spec;
	// it uses the existing client_secret path. AuthenticateClient suffices.
	var client *models.OAuthClient
	client, err = s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	requestingAgent, err := s.Storage.AgentByClientID(ctx, client.ClientID)
	if err != nil {
		return TokenResponse{}, models.ErrOAuthInvalidClient
	}
	if requestingAgent.Status != models.AgentStatusActive {
		return TokenResponse{}, models.ErrAgentInactive
	}
	// Steps 2 + 3: parse + verify subject token, extract claims.
	if req.SubjectToken == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.SubjectTokenType != "" && req.SubjectTokenType != models.TokenTypeAccessToken {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	now := time.Now().UTC()
	subjectClaims, err := jwt.Verify(req.SubjectToken, s.PublicKeyByKID, "", now)
	if err != nil {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	if subjectClaims.Iss != s.Cfg.Issuer {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	// Step 4: validate optional actor_token; when supplied, must name
	// this agent (defence-in-depth against a stolen client credential
	// being used in a different agent context).
	if req.ActorToken != "" {
		if req.ActorTokenType != "" && req.ActorTokenType != models.TokenTypeAccessToken {
			return TokenResponse{}, models.ErrOAuthInvalidRequest
		}
		actClaims, err := jwt.Verify(req.ActorToken, s.PublicKeyByKID, "", now)
		if err != nil {
			return TokenResponse{}, models.ErrActorTokenInvalid
		}
		expected := models.AgentSubjectPrefix + requestingAgent.ID.String()
		if actClaims.Sub != expected {
			return TokenResponse{}, models.ErrActorTokenInvalid
		}
	}
	// Step 5: resource binding. RFC 8707 + 8693 require the resource
	// parameter to equal the subject token's aud so audience confusion
	// is impossible across exchange.
	resourceID := req.Resource
	if resourceID == "" {
		resourceID = subjectClaims.Aud
	}
	if resourceID == "" || resourceID != subjectClaims.Aud {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	if _, ok := s.ResourceByIdentifier(resourceID); !ok {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	// Step 5b (RFC 8693 section 2.1): when the caller specifies an
	// audience parameter, it must name a known resource. This prevents
	// audience-confusion attacks where the caller requests a token for a
	// resource the AS does not manage.
	if req.Audience != "" {
		if _, ok := s.ResourceByIdentifier(req.Audience); !ok {
			return TokenResponse{}, models.ErrOAuthInvalidResource
		}
	}
	// Step 6: resolve the principal (root subject of the chain) and
	// walk the existing actor chain to verify each link is still
	// active.
	root, existingChain, err := s.resolveSubjectPrincipal(ctx, subjectClaims)
	if err != nil {
		return TokenResponse{}, err
	}
	// Step 7: chain depth. The new chain prepends the requesting agent.
	// MaxActorChainDepth from JWTBearerConfig takes precedence when set;
	// otherwise fall back to AgentPolicy.MaxChainDepth.
	maxDepth := s.AgentPolicy.MaxChainDepth
	if s.Cfg.JWTBearer != nil && s.Cfg.JWTBearer.MaxActorChainDepth > 0 {
		maxDepth = s.Cfg.JWTBearer.MaxActorChainDepth
	}
	newDepth := chain.Depth(existingChain) + 1
	if newDepth > maxDepth {
		return TokenResponse{}, models.ErrChainDepthExceeded
	}
	// Step 8: locate delegation_grants for (root_user, requesting_agent,
	// resource). Sub-delegation (subject is itself an agent token) still
	// requires the requesting agent to hold a grant from the root user.
	grant, err := s.Storage.DelegationGrantByUserAgentResource(ctx, root, requestingAgent.ID, resourceID)
	if err != nil {
		return TokenResponse{}, models.ErrDelegationNotFound
	}
	if !delegation.Active(grant, now) {
		return TokenResponse{}, models.ErrDelegationRevoked
	}
	// Step 9: scope narrowing. Requested must be subset of subject's
	// scope AND the delegation's scope_grant.
	subjectScope := scopeSplit(subjectClaims.Scope)
	finalScope, ok := delegation.NarrowScope(req.Scope, subjectScope, grant.Scope)
	if !ok || len(finalScope) == 0 {
		return TokenResponse{}, models.ErrOAuthInvalidScope
	}
	// Step 10: duration tightening. exp = strict-min of every policy
	// bound.
	subjectExp := time.Unix(subjectClaims.Exp, 0)
	policyExp := chain.TightenDuration(
		subjectExp,
		now.Add(s.AgentPolicy.DefaultDelegatedTokenTTL),
		now.Add(time.Duration(grant.MaxDurationSeconds)*time.Second),
		now.Add(s.Cfg.AccessTokenTTL),
	)
	if policyExp.Before(now) || policyExp.Equal(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Step 11: build the new actor claim and mint.
	existingActor := actorFromClaims(subjectClaims)
	newActor := chain.Prepend(models.AgentSubjectPrefix+requestingAgent.ID.String(), existingActor)
	signingKey, priv, err := s.CurrentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	jti := ulid.New().String()
	claims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      subjectClaims.Sub,
		Aud:      resourceID,
		Exp:      policyExp.Unix(),
		Iat:      now.Unix(),
		Jti:      jti,
		ClientID: client.ClientID,
		Scope:    scopeJoin(finalScope),
		Typ:      jwt.TypeAccessToken,
		Extra: map[string]any{
			"act":                 actorClaimToMap(newActor),
			"delegation_grant_id": grant.ID.String(),
		},
	}
	if err := s.applyOnTokenIssued(ctx, &claims); err != nil {
		return TokenResponse{}, err
	}
	access, err := jwt.Sign(claims, signingKey.KID, priv)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign exchanged token: %w", err)
	}
	_ = s.Storage.UpdateAgentLastActive(ctx, requestingAgent.ID, now)
	s.Audit.EmitAudit(ctx, "token.exchanged", models.TargetRef{Type: "delegation_grant", ID: grant.ID.String()}, map[string]any{
		"grant_id":     grant.ID.String(),
		"actor_agent":  requestingAgent.ID.String(),
		"root_subject": root.String(),
		"resource":     resourceID,
		"scope":        finalScope,
		"chain_depth":  newDepth,
		"jti":          jti,
	})
	return TokenResponse{
		AccessToken:     access,
		TokenType:       "Bearer",
		ExpiresIn:       int(time.Until(policyExp).Seconds()),
		Scope:           scopeJoin(finalScope),
		IssuedTokenType: models.TokenTypeAccessToken,
	}, nil
}

// resolveSubjectPrincipal walks the subject token's claims and returns
// the root user ULID plus the existing actor chain (innermost-first).
// The subject token's sub is either a user ULID (direct user
// delegation) or "agent:<id>" (sub-delegation: an agent presenting
// another agent's token, which the spec forbids because the root
// subject MUST be a user). Returns ErrSubjectTokenInvalid if the chain
// has no user at the root.
//
// Every existing actor in the chain MUST currently be active; a
// suspended or revoked agent in the chain rejects the exchange
// immediately.
func (s *Service) resolveSubjectPrincipal(ctx context.Context, subjectClaims jwt.Claims) (models.ULID, *chain.Actor, error) {
	if subjectClaims.Sub == "" {
		return models.ULID{}, nil, models.ErrSubjectTokenInvalid
	}
	if strings.HasPrefix(subjectClaims.Sub, models.AgentSubjectPrefix) {
		// Root subject must be a user; agent-rooted tokens cannot seed
		// a delegation chain because there is no user authority behind
		// them.
		return models.ULID{}, nil, models.ErrSubjectTokenInvalid
	}
	root, err := parseULID(subjectClaims.Sub)
	if err != nil {
		return models.ULID{}, nil, models.ErrSubjectTokenInvalid
	}
	existing := actorFromClaims(subjectClaims)
	// Walk the existing chain and verify every actor is still active.
	for cur := existing; cur != nil; cur = cur.Act {
		ag, err := s.lookupAgent(ctx, cur.Sub)
		if err != nil {
			return models.ULID{}, nil, models.ErrSubjectTokenInvalid
		}
		if ag == nil {
			// Non-agent actor: only "agent:<id>" actors are emitted by
			// this AS; anything else means a forged or non-AS-issued
			// token.
			return models.ULID{}, nil, models.ErrSubjectTokenInvalid
		}
		if ag.Status != models.AgentStatusActive {
			return models.ULID{}, nil, models.ErrAgentInactive
		}
	}
	return root, existing, nil
}

// narrowDelegatedScope + delegationActive previously lived here as
// duplicates of the root service_delegation.go helpers. PR C of the
// 2026-06 architecture reorg consolidated both into
// internal/delegation; this file now imports delegation.NarrowScope and
// delegation.Active so the helpers exist in exactly one place.

// actorFromClaims reads the "act" extra claim from a JWT and returns
// the chain.Actor pointer (nil if not present or malformed). The
// on-the-wire shape is the RFC 8693 {sub, act?} nesting.
func actorFromClaims(c jwt.Claims) *chain.Actor {
	raw, ok := c.Extra["act"]
	if !ok || raw == nil {
		return nil
	}
	return actorFromAny(raw)
}

func actorFromAny(raw any) *chain.Actor {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	sub, _ := m["sub"].(string)
	if sub == "" {
		return nil
	}
	out := &chain.Actor{Sub: sub}
	if inner, ok := m["act"]; ok {
		out.Act = actorFromAny(inner)
	}
	return out
}

// actorClaimToMap renders an Actor chain as the {sub, act?} JSON shape
// the JWT marshaller expects in Claims.Extra.
func actorClaimToMap(a *chain.Actor) map[string]any {
	if a == nil {
		return nil
	}
	out := map[string]any{"sub": a.Sub}
	if a.Act != nil {
		out["act"] = actorClaimToMap(a.Act)
	}
	return out
}

func parseULID(s string) (models.ULID, error) {
	var z models.ULID
	if err := z.UnmarshalText([]byte(s)); err != nil {
		return models.ULID{}, err
	}
	return z, nil
}

func ptrToString(p *models.ULID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

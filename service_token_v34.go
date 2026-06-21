package theauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/chain"
	"github.com/glincker/theauth-go/internal/jwt"
	"github.com/glincker/theauth-go/internal/ulid"
)

// service_token_v34.go: v2.0 phase 3 + 4 grants. Adds the OAuth 2.0
// client_credentials grant (phase 3) and the RFC 8693 token-exchange grant
// (phase 4) to the existing /oauth/token multiplexer.

// TokenExchangeRequest is the parsed form-encoded body of a token-exchange
// call. Field names map 1:1 onto the RFC 8693 wire form.
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
// agents fail with ErrAgentInactive (mapped to access_denied at the wire).
//
// Audit emission: agent.token_minted on success.
func (a *TheAuth) ClientCredentialsToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if a.agentCfg == nil {
		return TokenResponse{}, ErrOAuthUnsupportedGrantType
	}
	client, err := a.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	agent, err := a.as.storage.AgentByClientID(ctx, client.ClientID)
	if err != nil {
		return TokenResponse{}, ErrOAuthInvalidClient
	}
	if agent.Status != AgentStatusActive {
		return TokenResponse{}, ErrAgentInactive
	}
	if req.Resource == "" {
		return TokenResponse{}, ErrOAuthInvalidResource
	}
	resource, ok := a.resourceByIdentifier(req.Resource)
	if !ok {
		return TokenResponse{}, ErrOAuthInvalidResource
	}
	// Scope narrowing: request must be a subset of the agent's permitted
	// scope set AND the resource catalog. Empty request means "issue the
	// intersection".
	registered := scopeSplit(client.Scope)
	if len(registered) == 0 {
		registered = agent.Scope
	}
	available := chain.ScopeIntersect(registered, resource.Scopes)
	requested := req.Scope
	if len(requested) == 0 {
		requested = available
	} else if !chain.ScopeSubset(requested, available) {
		return TokenResponse{}, ErrOAuthInvalidScope
	}
	if len(requested) == 0 {
		return TokenResponse{}, ErrOAuthInvalidScope
	}
	now := time.Now().UTC()
	jti := ulid.New().String()
	signingKey, priv, err := a.currentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	claims := jwt.Claims{
		Iss:      a.as.cfg.Issuer,
		Sub:      AgentSubjectPrefix + agent.ID.String(),
		Aud:      req.Resource,
		Exp:      now.Add(a.as.cfg.AccessTokenTTL).Unix(),
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
	access, err := jwt.Sign(claims, signingKey.KID, priv)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign agent token: %w", err)
	}
	_ = a.as.storage.UpdateAgentLastActive(ctx, agent.ID, now)
	a.EmitAudit(ctx, "agent.token_minted", TargetRef{Type: "agent", ID: agent.ID.String()}, map[string]any{
		"agent_id":  agent.ID.String(),
		"client_id": client.ClientID,
		"jti":       jti,
		"resource":  req.Resource,
		"scope":     requested,
		"grant":     GrantTypeClientCredentials,
	})
	return TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(a.as.cfg.AccessTokenTTL.Seconds()),
		Scope:       scopeJoin(requested),
	}, nil
}

// ExchangeToken implements RFC 8693 token exchange. The authenticated
// client (an agent's OAuth client) presents:
//   - subject_token: a JWT issued by this AS naming the principal the
//     mint is acting on behalf of. The principal may be a user or another
//     agent (sub-delegation). Required.
//   - actor_token: the agent's own self-token (issued via the
//     client_credentials grant). Optional but recommended; when present its
//     sub MUST match "agent:<id>" of the authenticated client.
//   - resource: the RFC 8707 binding. MUST match the subject token's aud.
//   - scope: optional narrowing. Default to the intersection of
//     (subject_scope, delegation.scope_grant).
//
// The eleven step validation in spec section 7 is enforced; see the
// individual sub-helpers below.
func (a *TheAuth) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (TokenResponse, error) {
	if a.as == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if a.agentCfg == nil {
		return TokenResponse{}, ErrOAuthUnsupportedGrantType
	}
	// Step 1: authenticate the requesting client (the agent).
	client, err := a.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	requestingAgent, err := a.as.storage.AgentByClientID(ctx, client.ClientID)
	if err != nil {
		return TokenResponse{}, ErrOAuthInvalidClient
	}
	if requestingAgent.Status != AgentStatusActive {
		return TokenResponse{}, ErrAgentInactive
	}
	// Steps 2 + 3: parse + verify subject token, extract claims.
	if req.SubjectToken == "" {
		return TokenResponse{}, ErrOAuthInvalidRequest
	}
	if req.SubjectTokenType != "" && req.SubjectTokenType != TokenTypeAccessToken {
		return TokenResponse{}, ErrOAuthInvalidRequest
	}
	now := time.Now().UTC()
	subjectClaims, err := jwt.Verify(req.SubjectToken, a.publicKeyByKID, "", now)
	if err != nil {
		return TokenResponse{}, ErrSubjectTokenInvalid
	}
	if subjectClaims.Iss != a.as.cfg.Issuer {
		return TokenResponse{}, ErrSubjectTokenInvalid
	}
	// Step 4: validate optional actor_token; when supplied, must name this
	// agent (defence-in-depth against a stolen client credential being used
	// in a different agent context).
	if req.ActorToken != "" {
		if req.ActorTokenType != "" && req.ActorTokenType != TokenTypeAccessToken {
			return TokenResponse{}, ErrOAuthInvalidRequest
		}
		actClaims, err := jwt.Verify(req.ActorToken, a.publicKeyByKID, "", now)
		if err != nil {
			return TokenResponse{}, ErrActorTokenInvalid
		}
		expected := AgentSubjectPrefix + requestingAgent.ID.String()
		if actClaims.Sub != expected {
			return TokenResponse{}, ErrActorTokenInvalid
		}
	}
	// Step 5: resource binding. RFC 8707 + 8693 require the resource
	// parameter to equal the subject token's aud so audience confusion is
	// impossible across exchange.
	resourceID := req.Resource
	if resourceID == "" {
		resourceID = subjectClaims.Aud
	}
	if resourceID == "" || resourceID != subjectClaims.Aud {
		return TokenResponse{}, ErrOAuthInvalidResource
	}
	if _, ok := a.resourceByIdentifier(resourceID); !ok {
		return TokenResponse{}, ErrOAuthInvalidResource
	}
	// Step 6: resolve the principal (root subject of the chain) and walk
	// the existing actor chain to verify each link is still active.
	root, existingChain, err := a.resolveSubjectPrincipal(ctx, subjectClaims)
	if err != nil {
		return TokenResponse{}, err
	}
	// Step 7: chain depth. The new chain prepends the requesting agent.
	newDepth := chain.Depth(existingChain) + 1
	if newDepth > a.agentCfg.MaxChainDepth {
		return TokenResponse{}, ErrChainDepthExceeded
	}
	// Step 8: locate delegation_grants for (root_user, requesting_agent,
	// resource). Sub-delegation (subject is itself an agent token) still
	// requires the requesting agent to hold a grant from the root user.
	grant, err := a.as.storage.DelegationGrantByUserAgentResource(ctx, root, requestingAgent.ID, resourceID)
	if err != nil {
		return TokenResponse{}, ErrDelegationNotFound
	}
	if !delegationActive(grant, now) {
		return TokenResponse{}, ErrDelegationRevoked
	}
	// Step 9: scope narrowing. Requested must be subset of subject's scope
	// AND the delegation's scope_grant.
	subjectScope := scopeSplit(subjectClaims.Scope)
	finalScope, ok := narrowDelegatedScope(req.Scope, subjectScope, grant.Scope)
	if !ok || len(finalScope) == 0 {
		return TokenResponse{}, ErrOAuthInvalidScope
	}
	// Step 10: duration tightening. exp = strict-min of every policy bound.
	subjectExp := time.Unix(subjectClaims.Exp, 0)
	policyExp := chain.TightenDuration(
		subjectExp,
		now.Add(a.agentCfg.DefaultDelegatedTokenTTL),
		now.Add(time.Duration(grant.MaxDurationSeconds)*time.Second),
		now.Add(a.as.cfg.AccessTokenTTL),
	)
	if policyExp.Before(now) || policyExp.Equal(now) {
		return TokenResponse{}, ErrOAuthInvalidGrant
	}
	// Step 11: build the new actor claim and mint.
	existingActor := actorFromClaims(subjectClaims)
	newActor := chain.Prepend(AgentSubjectPrefix+requestingAgent.ID.String(), existingActor)
	signingKey, priv, err := a.currentSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}
	jti := ulid.New().String()
	claims := jwt.Claims{
		Iss:      a.as.cfg.Issuer,
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
	access, err := jwt.Sign(claims, signingKey.KID, priv)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign exchanged token: %w", err)
	}
	_ = a.as.storage.UpdateAgentLastActive(ctx, requestingAgent.ID, now)
	a.EmitAudit(ctx, "token.exchanged", TargetRef{Type: "delegation_grant", ID: grant.ID.String()}, map[string]any{
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
		IssuedTokenType: TokenTypeAccessToken,
	}, nil
}

// resolveSubjectPrincipal walks the subject token's claims and returns the
// root user ULID plus the existing actor chain (innermost-first). The
// subject token's sub is either a user ULID (direct user delegation) or
// "agent:<id>" (sub-delegation: an agent presenting another agent's token,
// which the spec forbids because the root subject MUST be a user). Returns
// ErrSubjectTokenInvalid if the chain has no user at the root.
//
// Every existing actor in the chain MUST currently be active; a suspended
// or revoked agent in the chain rejects the exchange immediately.
func (a *TheAuth) resolveSubjectPrincipal(ctx context.Context, subjectClaims jwt.Claims) (ULID, *chain.Actor, error) {
	if subjectClaims.Sub == "" {
		return ULID{}, nil, ErrSubjectTokenInvalid
	}
	if strings.HasPrefix(subjectClaims.Sub, AgentSubjectPrefix) {
		// Root subject must be a user; agent-rooted tokens cannot seed a
		// delegation chain because there is no user authority behind them.
		return ULID{}, nil, ErrSubjectTokenInvalid
	}
	root, err := parseULID(subjectClaims.Sub)
	if err != nil {
		return ULID{}, nil, ErrSubjectTokenInvalid
	}
	existing := actorFromClaims(subjectClaims)
	// Verify every actor in the existing chain is still active.
	chain.Walk(existing, func(ac *chain.Actor) bool {
		// Loop continues until the closure returns false.
		return true
	})
	// We need to surface errors from the walk so do it in a plain loop too.
	for cur := existing; cur != nil; cur = cur.Act {
		ag, err := a.agentBySubjectClaim(ctx, cur.Sub)
		if err != nil {
			return ULID{}, nil, ErrSubjectTokenInvalid
		}
		if ag == nil {
			// Non-agent actor: only "agent:<id>" actors are emitted by this
			// AS; anything else means a forged or non-AS-issued token.
			return ULID{}, nil, ErrSubjectTokenInvalid
		}
		if ag.Status != AgentStatusActive {
			return ULID{}, nil, ErrAgentInactive
		}
	}
	return root, existing, nil
}

// actorFromClaims reads the "act" extra claim from a JWT and returns the
// chain.Actor pointer (nil if not present or malformed). The on-the-wire
// shape is the RFC 8693 {sub, act?} nesting.
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

// actorClaimToMap renders an Actor chain as the {sub, act?} JSON shape the
// JWT marshaller expects in Claims.Extra.
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

func parseULID(s string) (ULID, error) {
	// theauth.ULID is github.com/oklog/ulid/v2.ULID via the type alias in
	// models.go; calling Parse on the underlying type is enough.
	var z ULID
	if err := z.UnmarshalText([]byte(s)); err != nil {
		return ULID{}, err
	}
	return z, nil
}

func ptrToString(p *ULID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

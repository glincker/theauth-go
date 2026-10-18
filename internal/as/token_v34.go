package as

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/chain"
	"github.com/glincker/theauth-go/v2/internal/delegation"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// token_v34.go implements the phase 3 and 4 grants: client_credentials for agents and RFC 8693
// token exchange, on the same /oauth/token endpoint.

// TokenExchangeRequest is the parsed form body of a token exchange call, with RFC 8693 field names.
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

	// DPoPProof, HTTPMethod and HTTPURL carry the DPoP header and the method and URL it must bind to.
	// They are required when the subject token is DPoP bound.
	DPoPProof  string
	HTTPMethod string
	HTTPURL    string
}

// ClientCredentialsToken mints a self-token for an authenticated agent client. sub is "agent:<id>",
// aud is bound to the resource (RFC 8707), and scope is the intersection of the agent's scopes and
// the resource catalog. Suspended or revoked agents fail with ErrAgentInactive (access_denied on
// the wire). It emits agent.token_minted on success.
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
	if aerr := agentLiveErr(agent, s.now()); aerr != nil {
		return TokenResponse{}, aerr
	}
	// OptionalResource and PathAudience apply here as on the authorization code grant. audience is the
	// canonical identifier.
	resource, audience, rerr := s.resolveResource(req.Resource)
	if rerr != nil {
		return TokenResponse{}, rerr
	}
	// The requested scope must be a subset of the agent's permitted scopes and the resource catalog.
	// An empty request means the intersection.
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
	gated, gerr := s.gateMint(ctx, *agent, models.AgentMintClientCredentials, audience, requested, len(req.Scope) > 0, nil)
	if gerr != nil {
		return TokenResponse{}, gerr
	}
	requested = gated.Scopes
	now := time.Now().UTC()
	// The token never outlives the agent.
	accessExp := capExpiry(now.Add(s.Cfg.AccessTokenTTL), agentExpiryBound(agent))
	jti := ulid.New().String()
	claims := jwt.Claims{
		Iss:      s.Cfg.Issuer,
		Sub:      models.AgentSubjectPrefix + agent.ID.String(),
		Aud:      audience,
		Exp:      accessExp.Unix(),
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
	auditMeta := map[string]any{
		"agent_id":  agent.ID.String(),
		"client_id": client.ClientID,
		"jti":       jti,
		"resource":  audience,
		"scope":     requested,
		"grant":     models.GrantTypeClientCredentials,
	}
	addAgentPolicy(claims.Extra, auditMeta, gated)
	if err := s.applyOnTokenIssued(ctx, &claims); err != nil {
		return TokenResponse{}, err
	}
	access, err := s.issueAccessToken(ctx, client.ClientID, claims)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign agent token: %w", err)
	}
	s.touchAgentLastActive(ctx, agent.ID, now)
	s.Audit.EmitAudit(ctx, "agent.token_minted", models.TargetRef{Type: "agent", ID: agent.ID.String()}, auditMeta)
	return TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessExp.Sub(now).Seconds()),
		Scope:       scopeJoin(requested),
	}, nil
}

// ExchangeToken implements RFC 8693 token exchange. The authenticated agent client presents a
// subject_token (a JWT this AS issued, naming the principal acted for; required), an optional
// actor_token that must name this agent, the resource (which must match the subject aud), and an
// optional narrowed scope. The validation steps of spec section 7 run in order.
func (s *Service) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (resp TokenResponse, err error) {
	if s == nil {
		return TokenResponse{}, errors.New("theauth: authorization server not configured")
	}
	if req.RequestedTokenType == models.TokenTypeIDJAG {
		return s.exchangeForIDJAG(ctx, req)
	}
	if s.AgentPolicy == nil {
		return TokenResponse{}, models.ErrOAuthUnsupportedGrantType
	}
	ctx, span, timer := s.startTokenSpan(ctx, "token-exchange")
	defer func() { s.finishTokenSpan(span, timer, "token-exchange", err) }()
	// Step 1: authenticate the requesting agent. Token exchange uses the client_secret path, not JWT
	// client assertions.
	var client *models.OAuthClient
	client, err = s.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	requestingAgent, err := s.Storage.AgentByClientID(ctx, client.ClientID)
	if err != nil {
		return TokenResponse{}, models.ErrOAuthInvalidClient
	}
	if aerr := agentLiveErr(requestingAgent, s.now()); aerr != nil {
		return TokenResponse{}, aerr
	}
	// Steps 2 and 3: parse and verify the subject token, then extract its claims.
	if req.SubjectToken == "" {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	if req.SubjectTokenType != "" && req.SubjectTokenType != models.TokenTypeAccessToken {
		return TokenResponse{}, models.ErrOAuthInvalidRequest
	}
	now := time.Now().UTC()
	subjectClaims, err := s.verifyAccessJWT(req.SubjectToken, "", now)
	if err != nil {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	if subjectClaims.Iss != s.Cfg.Issuer {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	// A subject token revoked through /oauth/revoke cannot be exchanged for a fresh one.
	if s.accessJTIRevoked(ctx, subjectClaims.Jti) {
		return TokenResponse{}, models.ErrSubjectTokenInvalid
	}
	// RFC 9449: a DPoP-bound subject token may only be exchanged by the key holder. The new token
	// keeps the binding, so an exchange can never turn a sender-constrained token into a bearer token.
	subjectJKT := cnfJKT(subjectClaims.Extra)
	proofJKT, perr := s.dpopThumbprintForRequest(TokenRequest{
		ClientID:   client.ClientID,
		DPoPProof:  req.DPoPProof,
		HTTPMethod: req.HTTPMethod,
		HTTPURL:    req.HTTPURL,
	})
	if perr != nil {
		return TokenResponse{}, perr
	}
	if subjectJKT != "" && (proofJKT == "" || !jktEqual(proofJKT, subjectJKT)) {
		return TokenResponse{}, fmt.Errorf("%w: subject token is DPoP-bound, matching proof required", ErrDPoPInvalid)
	}
	// Step 4: an actor_token must name this agent. This blocks a stolen client credential from being
	// used in another agent's context.
	if req.ActorToken != "" {
		if req.ActorTokenType != "" && req.ActorTokenType != models.TokenTypeAccessToken {
			return TokenResponse{}, models.ErrOAuthInvalidRequest
		}
		actClaims, err := s.verifyAccessJWT(req.ActorToken, "", now)
		if err != nil {
			return TokenResponse{}, models.ErrActorTokenInvalid
		}
		expected := models.AgentSubjectPrefix + requestingAgent.ID.String()
		if actClaims.Sub != expected {
			return TokenResponse{}, models.ErrActorTokenInvalid
		}
	}
	// Step 5: the resource must equal the subject token aud (RFC 8707 and 8693), which prevents
	// audience confusion. PathAudience compares canonical identifiers; exact matches keep the old
	// behavior.
	resourceID := req.Resource
	if resourceID == "" {
		resourceID = subjectClaims.Aud
	}
	if resourceID == "" || subjectClaims.Aud == "" {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	_, resolvedAud, rerr := s.resolveResource(resourceID)
	if rerr != nil || resolvedAud != subjectClaims.Aud {
		return TokenResponse{}, models.ErrOAuthInvalidResource
	}
	resourceID = resolvedAud
	// Step 5b (RFC 8693 section 2.1): a requested audience must name a configured resource, so callers
	// cannot get tokens for unmanaged resources.
	if req.Audience != "" {
		if _, _, aerr := s.resolveResource(req.Audience); aerr != nil {
			return TokenResponse{}, models.ErrOAuthInvalidResource
		}
	}
	// Step 6: resolve the root principal and walk the existing actor chain to confirm every link is
	// still active.
	root, existingChain, chainExp, err := s.resolveSubjectPrincipal(ctx, subjectClaims, s.now())
	if err != nil {
		return TokenResponse{}, err
	}
	// Step 7: chain depth. The new chain prepends the requesting agent.
	// JWTBearerConfig.MaxActorChainDepth wins when set.
	maxDepth := s.AgentPolicy.MaxChainDepth
	if s.Cfg.JWTBearer != nil && s.Cfg.JWTBearer.MaxActorChainDepth > 0 {
		maxDepth = s.Cfg.JWTBearer.MaxActorChainDepth
	}
	newDepth := chain.Depth(existingChain) + 1
	if newDepth > maxDepth {
		return TokenResponse{}, models.ErrChainDepthExceeded
	}
	// Step 8: find the delegation grant for (root user, requesting agent, resource). Sub-delegation
	// still needs such a grant.
	grant, err := s.Storage.DelegationGrantByUserAgentResource(ctx, root, requestingAgent.ID, resourceID)
	if err != nil {
		return TokenResponse{}, models.ErrDelegationNotFound
	}
	if !delegation.Active(grant, now) {
		return TokenResponse{}, models.ErrDelegationRevoked
	}
	// Step 9: scope narrowing. The request must be a subset of the subject scope and the delegation scope grant.
	subjectScope := scopeSplit(subjectClaims.Scope)
	finalScope, ok := delegation.NarrowScope(req.Scope, subjectScope, grant.Scope)
	if !ok || len(finalScope) == 0 {
		return TokenResponse{}, models.ErrOAuthInvalidScope
	}
	gated, gerr := s.gateMint(ctx, *requestingAgent, models.AgentMintTokenExchange, resourceID, finalScope, len(req.Scope) > 0, nil)
	if gerr != nil {
		return TokenResponse{}, gerr
	}
	finalScope = gated.Scopes
	// Step 10: duration tightening. exp is the earliest of every policy bound.
	subjectExp := time.Unix(subjectClaims.Exp, 0)
	policyExp := chain.TightenDuration(
		subjectExp,
		now.Add(s.AgentPolicy.DefaultDelegatedTokenTTL),
		now.Add(time.Duration(grant.MaxDurationSeconds)*time.Second),
		now.Add(s.Cfg.AccessTokenTTL),
		agentExpiryBound(requestingAgent),
		chainExp,
	)
	if policyExp.Before(now) || policyExp.Equal(now) {
		return TokenResponse{}, models.ErrOAuthInvalidGrant
	}
	// Step 11: build the new actor claim and mint.
	existingActor := actorFromClaims(subjectClaims)
	newActor := chain.Prepend(models.AgentSubjectPrefix+requestingAgent.ID.String(), existingActor)
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
	exchangeMeta := map[string]any{
		"grant_id":     grant.ID.String(),
		"actor_agent":  requestingAgent.ID.String(),
		"root_subject": root.String(),
		"resource":     resourceID,
		"scope":        finalScope,
		"chain_depth":  newDepth,
		"jti":          jti,
	}
	addAgentPolicy(claims.Extra, exchangeMeta, gated)
	exchangedType := "Bearer"
	if proofJKT != "" {
		claims.Extra["cnf"] = map[string]string{"jkt": proofJKT}
		exchangedType = "DPoP"
	}
	if err := s.applyOnTokenIssued(ctx, &claims); err != nil {
		return TokenResponse{}, err
	}
	access, err := s.issueAccessToken(ctx, client.ClientID, claims)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sign exchanged token: %w", err)
	}
	s.touchAgentLastActive(ctx, requestingAgent.ID, now)
	s.Audit.EmitAudit(ctx, "token.exchanged", models.TargetRef{Type: "delegation_grant", ID: grant.ID.String()}, exchangeMeta)
	return TokenResponse{
		AccessToken:     access,
		TokenType:       exchangedType,
		ExpiresIn:       int(policyExp.Sub(now).Seconds()),
		Scope:           scopeJoin(finalScope),
		IssuedTokenType: models.TokenTypeAccessToken,
	}, nil
}

// resolveSubjectPrincipal walks the subject token's claims and returns the root user and the
// existing actor chain, innermost first. The root must be a user, since no user authority stands
// behind an agent-rooted token. Every actor in the chain must be active and unexpired. The earliest
// actor expiry is returned (zero when none) so the caller can cap the new token.
func (s *Service) resolveSubjectPrincipal(ctx context.Context, subjectClaims jwt.Claims, now time.Time) (models.ULID, *chain.Actor, time.Time, error) {
	if subjectClaims.Sub == "" {
		return models.ULID{}, nil, time.Time{}, models.ErrSubjectTokenInvalid
	}
	if strings.HasPrefix(subjectClaims.Sub, models.AgentSubjectPrefix) {
		// An agent-rooted token cannot seed a delegation chain, because no user authority stands behind it.
		return models.ULID{}, nil, time.Time{}, models.ErrSubjectTokenInvalid
	}
	root, err := parseULID(subjectClaims.Sub)
	if err != nil {
		return models.ULID{}, nil, time.Time{}, models.ErrSubjectTokenInvalid
	}
	existing := actorFromClaims(subjectClaims)
	var chainExp time.Time
	// Walk the existing chain and verify every actor is still active.
	for cur := existing; cur != nil; cur = cur.Act {
		ag, err := s.lookupAgent(ctx, cur.Sub)
		if err != nil {
			return models.ULID{}, nil, time.Time{}, models.ErrSubjectTokenInvalid
		}
		if ag == nil {
			// Only "agent:<id>" actors are emitted by this AS. Anything else means a forged or foreign token.
			return models.ULID{}, nil, time.Time{}, models.ErrSubjectTokenInvalid
		}
		if aerr := agentLiveErr(ag, now); aerr != nil {
			return models.ULID{}, nil, time.Time{}, aerr
		}
		chainExp = capExpiry(chainExp, agentExpiryBound(ag))
	}
	return root, existing, chainExp, nil
}

// actorFromClaims reads the act claim from a JWT and returns the chain actor, or nil when absent or
// malformed.
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

// actorClaimToMap renders an actor chain as the {sub, act} shape the JWT marshaller expects.
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

package theauth

import (
	"context"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_token_v34.go: thin forwarders for the v2.0 phase 3 + 4 grants
// (client_credentials and the RFC 8693 token-exchange). PR B
// architecture reorg (2026-06-20) moved the implementations into
// internal/as; the agent identity service that the token-exchange path
// consults still lives in root (it moves in PR C), so the AS service
// reaches *TheAuth.agentBySubjectClaim through the
// AgentLookup adapter wired in at theauth.New time.

// TokenExchangeRequest is the parsed form-encoded body of a
// token-exchange call. Field names map 1:1 onto the RFC 8693 wire form.
type TokenExchangeRequest = internalas.TokenExchangeRequest

// ClientCredentialsToken mints a self-token for the authenticated agent
// client. The token's sub is "agent:<id>"; aud is bound to the resource
// parameter (RFC 8707); scope is intersected with both the agent's
// registered scope set and the resource catalog. Suspended / revoked
// agents fail with ErrAgentInactive (mapped to access_denied at the
// wire).
//
// Audit emission: agent.token_minted on success.
func (a *TheAuth) ClientCredentialsToken(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	return a.as.ClientCredentialsToken(ctx, req)
}

// ExchangeToken implements RFC 8693 token exchange.
func (a *TheAuth) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (TokenResponse, error) {
	return a.as.ExchangeToken(ctx, req)
}

package sqlite

import theauth "github.com/glincker/theauth-go/v2"

// The OAuth 2.1 authorization server needs the whole OAuthServerStorage capability. The client, code,
// refresh token and JWKS half lives in as_*.go and the agent and delegation half in agents.go and
// delegations.go, so this assertion only holds once both halves are present.
var _ theauth.OAuthServerStorage = (*Store)(nil)

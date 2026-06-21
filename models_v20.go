package theauth

// Type, constant, and function aliases that re-export the v2.0 model layer
// (OAuth 2.1 AS primitives, agent identity, delegation, RFC 8693 actor
// claims) from github.com/glincker/theauth-go/internal/models. See the
// header comment on models.go for the rationale behind the alias form.

import "github.com/glincker/theauth-go/internal/models"

// ---------- v2.0 OAuth 2.1 AS primitives ----------

type ClientOwner = models.ClientOwner

type OAuthClient = models.OAuthClient

type AuthorizationCode = models.AuthorizationCode

type RefreshToken = models.RefreshToken

type JWKSKey = models.JWKSKey

// JWKS key state constants.
const (
	JWKSStateNext     = models.JWKSStateNext
	JWKSStateCurrent  = models.JWKSStateCurrent
	JWKSStatePrevious = models.JWKSStatePrevious
	JWKSStateRetired  = models.JWKSStateRetired
)

// Client owner kind constants persisted in oauth_clients.owner_kind.
const (
	ClientOwnerKindUser         = models.ClientOwnerKindUser
	ClientOwnerKindOrganization = models.ClientOwnerKindOrganization
	ClientOwnerKindAgent        = models.ClientOwnerKindAgent
	ClientOwnerKindAnonymous    = models.ClientOwnerKindAnonymous
)

// Client authentication method constants.
const (
	ClientAuthSecretBasic = models.ClientAuthSecretBasic
	ClientAuthSecretPost  = models.ClientAuthSecretPost
	ClientAuthNone        = models.ClientAuthNone
)

// Grant type constants.
const (
	GrantTypeAuthorizationCode = models.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = models.GrantTypeRefreshToken
	GrantTypeClientCredentials = models.GrantTypeClientCredentials
	GrantTypeTokenExchange     = models.GrantTypeTokenExchange
)

// Token type URNs used by the RFC 8693 token-exchange grant.
const (
	TokenTypeAccessToken = models.TokenTypeAccessToken
)

// Response type constants. OAuth 2.1 supports only "code".
const (
	ResponseTypeCode = models.ResponseTypeCode
)

// ---------- v2.0 phase 3 agent identity ----------

type AgentOwner = models.AgentOwner

type CreateAgentInput = models.CreateAgentInput

// Agent lifecycle status values persisted in agents.status.
const (
	AgentStatusActive    = models.AgentStatusActive
	AgentStatusSuspended = models.AgentStatusSuspended
	AgentStatusRevoked   = models.AgentStatusRevoked
)

// Agent credential kind constants persisted in agent_credentials.kind.
const (
	AgentCredentialKindSecret = models.AgentCredentialKindSecret
	AgentCredentialKindX509   = models.AgentCredentialKindX509
	AgentCredentialKindJWK    = models.AgentCredentialKindJWK
)

// AgentSubjectPrefix is prepended to an agent ID inside JWT sub and act.sub
// claims so resource servers can distinguish a user subject from an agent
// subject without consulting storage.
const AgentSubjectPrefix = models.AgentSubjectPrefix

type Agent = models.Agent

type AgentCredential = models.AgentCredential

type AgentSecret = models.AgentSecret

// ---------- v2.0 phase 4 delegation ----------

type DelegationGrant = models.DelegationGrant

type GrantDelegationInput = models.GrantDelegationInput

type ActorClaim = models.ActorClaim

// ---------- v2.0 resource + DCR types ----------

// ProtectedResource describes one resource server protected by this AS.
type ProtectedResource = models.ProtectedResource

// RegisteredClient is the JSON body returned on a successful registration
// (RFC 7591 section 3.2.1).
type RegisteredClient = models.RegisteredClient

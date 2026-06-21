package theauth

import "time"

// v2.0 (phase 1 + 2) model additions: OAuth 2.1 Authorization Server primitives.
// Agents, agent credentials, and delegation grants are deferred to phase 3 + 4
// and intentionally absent from this file. The owner_agent_id column on
// oauth_clients exists in migration 0011 to keep the table forward compatible,
// but is not populated by any v2.0 code path until phase 3 lands.

// ClientOwner identifies who owns an OAuth client registration. Exactly one
// pointer field is non-nil. AgentID is reserved for phase 3; phase 1 + 2
// clients are always owned by a user, an organization, or are anonymous DCR
// registrations (Owner is the zero value and AnonymousRegistered is true on
// the OAuthClient row).
type ClientOwner struct {
	UserID         *ULID
	OrganizationID *ULID
	AgentID        *ULID
}

// OAuthClient is one registration row backing the OAuth 2.1 authorization
// server. Persisted by RFC 7591 dynamic client registration (POST /oauth/register)
// and by future admin/account flows. Fields mirror RFC 7591 client metadata.
type OAuthClient struct {
	ID                      ULID        `json:"-"`
	ClientID                string      `json:"client_id"`
	ClientSecretHash        []byte      `json:"-"`
	ClientName              string      `json:"client_name"`
	RedirectURIs            []string    `json:"redirect_uris"`
	GrantTypes              []string    `json:"grant_types"`
	ResponseTypes           []string    `json:"response_types"`
	Scope                   string      `json:"scope"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method"`
	ApplicationType         string      `json:"application_type"`
	Contacts                []string    `json:"contacts,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    []byte      `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`
	Owner                   ClientOwner `json:"-"`
	AnonymousRegistered     bool        `json:"-"`
	RegistrationAccessHash  []byte      `json:"-"`
	CreatedAt               time.Time   `json:"client_id_issued_at,omitempty"`
	UpdatedAt               time.Time   `json:"-"`
}

// AuthorizationCode is a single-use 60-second TTL record bound to a client,
// user, redirect URI, scope, resource (RFC 8707), and PKCE challenge.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              ULID
	OrganizationID      *ULID
	RedirectURI         string
	Scope               []string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// RefreshToken is the opaque, hashed, rotated-on-use refresh artefact backing
// the refresh_token grant. FamilyID links rotated tokens; presenting an old
// token after rotation revokes the family per RFC 9700 section 4.14.
type RefreshToken struct {
	ID             ULID
	Hash           []byte
	FamilyID       ULID
	ClientID       string
	UserID         *ULID
	AgentID        *ULID
	Scope          []string
	Resource       string
	ParentJTI      string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	RevocationNote string
}

// JWKSKey is one signing key in the AS's JWKS state machine. State transitions:
// next -> current -> previous -> retired. The private key bytes are AES-GCM
// encrypted at rest using Config.EncryptionKey.
type JWKSKey struct {
	KID        string
	Alg        string // "EdDSA"
	Use        string // "sig"
	PublicJWK  []byte
	PrivateEnc []byte
	State      string // "next" | "current" | "previous" | "retired"
	CreatedAt  time.Time
	PromotedAt *time.Time
	RetiredAt  *time.Time
}

// JWKS key state constants.
const (
	JWKSStateNext     = "next"
	JWKSStateCurrent  = "current"
	JWKSStatePrevious = "previous"
	JWKSStateRetired  = "retired"
)

// Client owner kind constants persisted in oauth_clients.owner_kind.
const (
	ClientOwnerKindUser         = "user"
	ClientOwnerKindOrganization = "organization"
	ClientOwnerKindAgent        = "agent"
	ClientOwnerKindAnonymous    = "anonymous"
)

// Client authentication method constants advertised in AS metadata and used on
// /oauth/token client authentication.
const (
	ClientAuthSecretBasic = "client_secret_basic"
	ClientAuthSecretPost  = "client_secret_post"
	ClientAuthNone        = "none"
)

// Grant type constants. Phase 1 + 2 ships authorization_code and
// refresh_token; phase 3 adds client_credentials, phase 4 adds the
// RFC 8693 token-exchange grant URN.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Token type URNs used by the RFC 8693 token-exchange grant.
const (
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// Response type constants. OAuth 2.1 supports only "code".
const (
	ResponseTypeCode = "code"
)

// Agent identity (v2.0 phase 3). An agent is a long-lived, owner-bound
// identity with its own client credentials, separate audit identity, and
// lifecycle. Every agent has a backing OAuthClient row whose owner_kind is
// "agent"; client authentication paths converge on a single table.

// AgentOwner identifies who owns an agent. Exactly one of the pointer fields
// MUST be non-nil. A UserID-owned agent is a personal agent; an
// OrganizationID-owned agent is a service account.
type AgentOwner struct {
	UserID         *ULID
	OrganizationID *ULID
}

// CreateAgentInput is the input bundle for CreateAgent.
type CreateAgentInput struct {
	Owner       AgentOwner
	Name        string
	Description string
	// Scope is the set of scopes the agent may request via client credentials
	// or token exchange. Must be a subset of the resource's supported scopes
	// at mint time; the AS enforces this at every grant.
	Scope []string
}

// Agent lifecycle status values persisted in agents.status.
const (
	AgentStatusActive    = "active"
	AgentStatusSuspended = "suspended"
	AgentStatusRevoked   = "revoked"
)

// Agent credential kind constants persisted in agent_credentials.kind.
const (
	AgentCredentialKindSecret = "secret"
	AgentCredentialKindX509   = "x509"
	AgentCredentialKindJWK    = "jwk"
)

// AgentSubjectPrefix is prepended to an agent ID inside JWT sub and act.sub
// claims so resource servers can distinguish a user subject from an agent
// subject without consulting storage.
const AgentSubjectPrefix = "agent:"

// Agent is the persistent record for an agent identity.
type Agent struct {
	ID             ULID       `json:"id"`
	OwnerUserID    *ULID      `json:"ownerUserId,omitempty"`
	OrganizationID *ULID      `json:"organizationId,omitempty"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	Status         string     `json:"status"`
	ClientID       string     `json:"clientId"`
	Scope          []string   `json:"scope,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastActiveAt   *time.Time `json:"lastActiveAt,omitempty"`
}

// AgentCredential is one stored secret material row for an agent. For kind
// = "secret" the ValueEnc field carries the Argon2id PHC hash of the shared
// secret (cast to bytes); kinds "x509" and "jwk" are reserved for future
// phases.
type AgentCredential struct {
	ID         ULID       `json:"id"`
	AgentID    ULID       `json:"agentId"`
	Kind       string     `json:"kind"`
	ValueEnc   []byte     `json:"-"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// AgentSecret is the one-time return value from CreateAgent or
// RotateAgentSecret. The plaintext Secret is shown to the caller exactly
// once; only the Argon2id hash is persisted.
type AgentSecret struct {
	AgentID      ULID       `json:"agentId"`
	CredentialID ULID       `json:"credentialId"`
	ClientID     string     `json:"clientId"`
	Secret       string     `json:"secret"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
}

// DelegationGrant records "user U delegates scope S on resource R to agent A
// for at most max_duration_seconds, optionally bounded by expires_at". Token
// exchange consults this row at every mint; revocation flips RevokedAt and
// introspection on every resource request makes the change visible inside
// IntrospectionCacheTTL.
type DelegationGrant struct {
	ID                 ULID       `json:"id"`
	UserID             ULID       `json:"userId"`
	AgentID            ULID       `json:"agentId"`
	OrganizationID     *ULID      `json:"organizationId,omitempty"`
	Scope              []string   `json:"scope"`
	Resource           string     `json:"resource"`
	MaxDurationSeconds int        `json:"maxDurationSeconds"`
	CreatedAt          time.Time  `json:"createdAt"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	RevokedAt          *time.Time `json:"revokedAt,omitempty"`
	RevocationNote     string     `json:"revocationNote,omitempty"`
}

// GrantDelegationInput is the input bundle for GrantDelegation. UserID and
// AgentID are mandatory; Scope and Resource are mandatory and validated
// against the AS's configured ProtectedResources.
type GrantDelegationInput struct {
	UserID             ULID
	AgentID            ULID
	OrganizationID     *ULID
	Scope              []string
	Resource           string
	MaxDurationSeconds int
	ExpiresAt          *time.Time
}

// ActorClaim mirrors the RFC 8693 section 4.1 actor structure. The sub field
// names the immediate actor; act recurses outward through the chain so the
// outermost subject (the user who originally granted authority) is implicit
// in the surrounding JWT's sub.
type ActorClaim struct {
	Sub string      `json:"sub"`
	Act *ActorClaim `json:"act,omitempty"`
}

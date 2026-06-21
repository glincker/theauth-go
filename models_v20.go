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

// Grant type constants. Phase 1 + 2 supports authorization_code and
// refresh_token. client_credentials and token-exchange land in phase 3 + 4.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// Response type constants. OAuth 2.1 supports only "code".
const (
	ResponseTypeCode = "code"
)

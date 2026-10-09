package as

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// token_policy.go: per-client access token policy. A client can pick the JWS
// algorithm its JWT access tokens are signed with (so its resource servers
// can verify them with whatever their stack supports) and can ask for opaque
// reference tokens instead of JWTs. Both are opt-in: with no TokenPolicy
// configured every client keeps getting EdDSA JWTs.

// TokenPolicyConfig enables the per-client token policy.
type TokenPolicyConfig struct {
	// SigningAlgs lists the algorithms, beyond Config.SigningAlg, a client
	// may select with access_token_signed_response_alg (ES256, RS256 or
	// EdDSA). Keys for an algorithm are minted the first time a client
	// needs them.
	SigningAlgs []string

	// DefaultAccessTokenFormat is the format used for clients that do not
	// choose one: models.AccessTokenFormatJWT (default) or
	// models.AccessTokenFormatOpaque. Opaque needs a storage that
	// implements OpaqueTokenStorage.
	DefaultAccessTokenFormat string
}

// OpaqueTokenStorage is the optional persistence extension behind opaque
// access tokens. Only SHA-256 hashes of the tokens are stored.
type OpaqueTokenStorage interface {
	// InsertOpaqueAccessToken stores a newly issued token record.
	InsertOpaqueAccessToken(ctx context.Context, t models.OpaqueAccessToken) error

	// OpaqueAccessTokenByHash looks a record up by token hash. It returns
	// models.ErrStorageNotFound on a miss.
	OpaqueAccessTokenByHash(ctx context.Context, hash []byte) (*models.OpaqueAccessToken, error)

	// RevokeOpaqueAccessToken marks the record revoked. Revoking an unknown
	// or already revoked token is not an error.
	RevokeOpaqueAccessToken(ctx context.Context, hash []byte) error
}

func validateTokenPolicy(cfg *Config) error {
	p := cfg.TokenPolicy
	if p == nil {
		return nil
	}
	for _, alg := range p.SigningAlgs {
		if !jwt.SupportedAlg(alg) {
			return fmt.Errorf("theauth: TokenPolicy.SigningAlgs: unsupported alg %q", alg)
		}
	}
	switch p.DefaultAccessTokenFormat {
	case "":
		p.DefaultAccessTokenFormat = models.AccessTokenFormatJWT
	case models.AccessTokenFormatJWT, models.AccessTokenFormatOpaque:
	default:
		return fmt.Errorf("theauth: TokenPolicy.DefaultAccessTokenFormat: unknown format %q", p.DefaultAccessTokenFormat)
	}
	return nil
}

// opaqueStore returns the opaque token storage when the backend has it.
func (s *Service) opaqueStore() (OpaqueTokenStorage, bool) {
	st, ok := s.Storage.(OpaqueTokenStorage)
	return st, ok
}

// OpaqueTokensAvailable reports whether the policy is on and the storage can
// back reference tokens.
func (s *Service) OpaqueTokensAvailable() bool {
	if s == nil || s.Cfg.TokenPolicy == nil {
		return false
	}
	_, ok := s.opaqueStore()
	return ok
}

// SigningAlgsAdvertised lists every algorithm access tokens may be signed
// with, default first.
func (s *Service) SigningAlgsAdvertised() []string {
	out := []string{s.defaultSigningAlg()}
	if s.Cfg.TokenPolicy == nil {
		return out
	}
	for _, a := range s.Cfg.TokenPolicy.SigningAlgs {
		if a != out[0] {
			out = append(out, a)
		}
	}
	return out
}

// ValidateClientTokenPolicy checks the access token metadata of a client
// being registered. It returns nil for empty values.
func (s *Service) ValidateClientTokenPolicy(format, alg string) error {
	switch format {
	case "", models.AccessTokenFormatJWT:
	case models.AccessTokenFormatOpaque:
		if !s.OpaqueTokensAvailable() {
			return errors.New("opaque access tokens are not enabled")
		}
	default:
		return fmt.Errorf("unknown access_token_format %q", format)
	}
	if alg != "" {
		if !jwt.SupportedAlg(alg) {
			return fmt.Errorf("unsupported access_token_signed_response_alg %q", alg)
		}
		if s.Cfg.TokenPolicy == nil || !s.SigningAlgEnabled(alg) {
			return fmt.Errorf("access_token_signed_response_alg %q is not enabled on this server", alg)
		}
	}
	return nil
}

// accessTokenPolicy resolves the effective format and algorithm for a client.
// A client that cannot be loaded (for example a CIMD client with no stored
// row) gets the server defaults.
func (s *Service) accessTokenPolicy(ctx context.Context, clientID string) (format, alg string) {
	format = models.AccessTokenFormatJWT
	alg = s.defaultSigningAlg()
	if s.Cfg.TokenPolicy == nil {
		return format, alg
	}
	if d := s.Cfg.TokenPolicy.DefaultAccessTokenFormat; d != "" {
		format = d
	}
	c, err := s.Storage.OAuthClientByClientID(ctx, clientID)
	if err != nil || c == nil {
		return format, alg
	}
	if c.AccessTokenFormat != "" {
		format = c.AccessTokenFormat
	}
	if c.AccessTokenSignedResponseAlg != "" && s.SigningAlgEnabled(c.AccessTokenSignedResponseAlg) {
		alg = c.AccessTokenSignedResponseAlg
	}
	return format, alg
}

// issueAccessToken encodes claims as the client's access token: a signed JWT
// or an opaque reference token. Every grant mints through here.
func (s *Service) issueAccessToken(ctx context.Context, clientID string, claims jwt.Claims) (string, error) {
	format, alg := s.accessTokenPolicy(ctx, clientID)
	if format == models.AccessTokenFormatOpaque {
		return s.issueOpaqueToken(ctx, clientID, claims)
	}
	key, signer, err := s.SigningKeyFor(ctx, alg)
	if err != nil {
		return "", err
	}
	return jwt.SignWith(claims, jwt.TypeAccessToken, key.KID, alg, signer)
}

func (s *Service) issueOpaqueToken(ctx context.Context, clientID string, claims jwt.Claims) (string, error) {
	store, ok := s.opaqueStore()
	if !ok {
		return "", errors.New("theauth: storage does not support opaque access tokens")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal opaque claims: %w", err)
	}
	token, err := crypto.NewToken()
	if err != nil {
		return "", fmt.Errorf("mint opaque token: %w", err)
	}
	jti := claims.Jti
	if jti == "" {
		jti = ulid.New().String()
	}
	rec := models.OpaqueAccessToken{
		Hash:      crypto.HashToken(token),
		JTI:       jti,
		ClientID:  clientID,
		Claims:    raw,
		IssuedAt:  timeFromUnix(claims.Iat),
		ExpiresAt: timeFromUnix(claims.Exp),
	}
	if err := store.InsertOpaqueAccessToken(ctx, rec); err != nil {
		return "", fmt.Errorf("store opaque token: %w", err)
	}
	return token, nil
}

// lookupOpaqueClaims resolves an opaque token to its claim set. ok is false
// for unknown, expired or revoked tokens.
func (s *Service) lookupOpaqueClaims(ctx context.Context, token string) (jwt.Claims, bool) {
	store, ok := s.opaqueStore()
	if !ok {
		return jwt.Claims{}, false
	}
	rec, err := store.OpaqueAccessTokenByHash(ctx, crypto.HashToken(token))
	if err != nil || rec == nil || rec.RevokedAt != nil {
		return jwt.Claims{}, false
	}
	if !rec.ExpiresAt.Add(s.Cfg.ClockSkew).After(s.Cfg.Clock.Now()) {
		return jwt.Claims{}, false
	}
	var c jwt.Claims
	if err := json.Unmarshal(rec.Claims, &c); err != nil {
		return jwt.Claims{}, false
	}
	return c, true
}

func timeFromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

package as

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// oidc.go: OpenID Provider core. ID token issuance, subject identifiers and
// the session linkage that logout needs. Userinfo and logout live in
// oidc_userinfo.go and oidc_logout.go.

// OIDC scope values handled by the provider.
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

// UserLookup resolves a local user for userinfo and logout tokens.
type UserLookup interface {
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
}

// OIDCEnabled reports whether the server acts as an OpenID Provider.
func (s *Service) OIDCEnabled() bool { return s != nil && s.Cfg.OIDC != nil }

func hasScope(scope []string, want string) bool { return slices.Contains(scope, want) }

// splitOIDCScopes separates the OIDC scopes, which are implicitly allowed,
// from the ones that must appear in the resource catalog.
func splitOIDCScopes(requested []string) (std, rest []string) {
	for _, sc := range requested {
		switch sc {
		case ScopeOpenID, ScopeProfile, ScopeEmail:
			std = append(std, sc)
		default:
			rest = append(rest, sc)
		}
	}
	return std, rest
}

// clientSubjectType resolves the effective subject type of a client.
func (s *Service) clientSubjectType(c *models.OAuthClient) string {
	if c != nil && c.SubjectType != "" {
		return c.SubjectType
	}
	if s.Cfg.OIDC != nil && s.Cfg.OIDC.DefaultSubjectType != "" {
		return s.Cfg.OIDC.DefaultSubjectType
	}
	return models.SubjectTypePublic
}

// sectorIdentifier is the host shared by the client's redirect URIs, or the
// client_id when there is none to use.
func sectorIdentifier(c *models.OAuthClient) string {
	for _, raw := range c.RedirectURIs {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return c.ClientID
}

// subjectFor returns the sub the client sees for userID: the local user id
// for public clients, an HMAC keyed by the pairwise salt and the client's
// sector otherwise.
func (s *Service) subjectFor(c *models.OAuthClient, userID string) string {
	if c == nil || s.Cfg.OIDC == nil || s.clientSubjectType(c) != models.SubjectTypePairwise || len(s.Cfg.OIDC.PairwiseSalt) == 0 {
		return userID
	}
	mac := hmac.New(sha256.New, s.Cfg.OIDC.PairwiseSalt)
	mac.Write([]byte(sectorIdentifier(c)))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sidFor derives the per client session identifier from the local session
// id, so two RPs cannot correlate a user by sid.
func (s *Service) sidFor(sessionID, clientID string) string {
	h := sha256.New()
	if s.Cfg.OIDC != nil {
		h.Write(s.Cfg.OIDC.PairwiseSalt)
	}
	h.Write([]byte{0})
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

// halfHash is the left half of the digest of v, base64url encoded, as used
// by at_hash. The digest follows the signing alg (OIDC Core 3.1.3.6).
func halfHash(alg, v string) string {
	var sum []byte
	if alg == jwt.AlgEdDSA {
		d := sha512.Sum512([]byte(v))
		sum = d[:]
	} else {
		d := sha256.Sum256([]byte(v))
		sum = d[:]
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// idTokenInput is what issueIDToken needs from a grant.
type idTokenInput struct {
	ClientID    string
	UserID      models.ULID
	AccessToken string
	Nonce       string
	SessionID   string
	AuthTime    time.Time
	ACR         string
	AMR         []string
}

// issueIDToken signs an ID token for the client. The signing alg follows the
// client's access token policy so one JWKS serves both.
func (s *Service) issueIDToken(ctx context.Context, in idTokenInput) (string, error) {
	client, err := s.ResolveClient(ctx, in.ClientID)
	if err != nil {
		return "", fmt.Errorf("resolve client: %w", err)
	}
	_, alg := s.accessTokenPolicy(ctx, in.ClientID)
	key, signer, err := s.SigningKeyFor(ctx, alg)
	if err != nil {
		return "", err
	}
	now := s.Cfg.Clock.Now().UTC()
	claims := map[string]any{
		"iss":     s.Cfg.Issuer,
		"sub":     s.subjectFor(client, in.UserID.String()),
		"aud":     in.ClientID,
		"iat":     now.Unix(),
		"exp":     now.Add(s.Cfg.OIDC.IDTokenTTL).Unix(),
		"at_hash": halfHash(alg, in.AccessToken),
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	if !in.AuthTime.IsZero() {
		claims["auth_time"] = in.AuthTime.Unix()
	}
	if in.ACR != "" {
		claims["acr"] = in.ACR
	}
	if len(in.AMR) > 0 {
		claims["amr"] = in.AMR
	}
	if in.SessionID != "" {
		claims["sid"] = s.sidFor(in.SessionID, in.ClientID)
	}
	return jwt.SignPayloadWith(claims, "JWT", key.KID, alg, signer)
}

// Session linkage. The authorization code row and the refresh token carry no
// session id, so the link lives in the shared cache for the life of the
// grant: code -> session, token family -> session, session -> clients. Losing
// an entry only drops sid and the back-channel notification for that grant.

const (
	oidcCodeKeyPrefix = "oidc:code:"
	oidcFamKeyPrefix  = "oidc:fam:"
	oidcSessKeyPrefix = "oidc:sess:"
)

func (s *Service) linkCodeSession(ctx context.Context, codeKey, sessionID string) {
	if s.oidcCache == nil || sessionID == "" {
		return
	}
	_ = s.oidcCache.Set(ctx, oidcCodeKeyPrefix+codeKey, []byte(sessionID), s.Cfg.AuthorizationCodeTTL+time.Minute)
}

func (s *Service) codeSession(ctx context.Context, codeKey string) string {
	if s.oidcCache == nil {
		return ""
	}
	v, ok, err := s.oidcCache.Get(ctx, oidcCodeKeyPrefix+codeKey)
	if err != nil || !ok {
		return ""
	}
	return string(v)
}

func (s *Service) familySession(ctx context.Context, familyID models.ULID) string {
	if s.oidcCache == nil {
		return ""
	}
	v, ok, err := s.oidcCache.Get(ctx, oidcFamKeyPrefix+familyID.String())
	if err != nil || !ok {
		return ""
	}
	return string(v)
}

// linkFamilySession records that the token family belongs to the session and
// that clientID took part in it.
func (s *Service) linkFamilySession(ctx context.Context, familyID models.ULID, sessionID, clientID string) {
	if s.oidcCache == nil || sessionID == "" {
		return
	}
	ttl := s.Cfg.RefreshTokenTTL
	_ = s.oidcCache.Set(ctx, oidcFamKeyPrefix+familyID.String(), []byte(sessionID), ttl)
	clients := s.sessionClients(ctx, sessionID)
	if slices.Contains(clients, clientID) {
		return
	}
	raw, err := json.Marshal(append(clients, clientID))
	if err == nil {
		_ = s.oidcCache.Set(ctx, oidcSessKeyPrefix+sessionID, raw, ttl)
	}
}

func (s *Service) sessionClients(ctx context.Context, sessionID string) []string {
	if s.oidcCache == nil {
		return nil
	}
	v, ok, err := s.oidcCache.Get(ctx, oidcSessKeyPrefix+sessionID)
	if err != nil || !ok {
		return nil
	}
	var out []string
	if json.Unmarshal(v, &out) != nil {
		return nil
	}
	return out
}

// validateOIDCMetadata vets the OIDC client metadata of a registration.
func (s *Service) validateOIDCMetadata(req ClientRegistrationRequest, anonymous bool) error {
	set := req.SubjectType != "" || len(req.PostLogoutRedirectURIs) > 0 ||
		req.BackchannelLogoutURI != "" || req.BackchannelLogoutSessionRequired
	if !set {
		return nil
	}
	if s.Cfg.OIDC == nil {
		return wrapInvalidReg("OpenID Connect metadata needs Config.OIDC")
	}
	if anonymous {
		return wrapInvalidReg("OpenID Connect metadata needs an authenticated registration")
	}
	switch req.SubjectType {
	case "", models.SubjectTypePublic:
	case models.SubjectTypePairwise:
		if len(s.Cfg.OIDC.PairwiseSalt) == 0 {
			return wrapInvalidReg("pairwise subjects are not enabled on this server")
		}
		if !singleHost(req.RedirectURIs) {
			return wrapInvalidReg("pairwise clients must register redirect URIs on a single host")
		}
	default:
		return wrapInvalidReg("unsupported subject_type: " + req.SubjectType)
	}
	for _, u := range req.PostLogoutRedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return err
		}
	}
	if u := req.BackchannelLogoutURI; u != "" {
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || p.Fragment != "" || p.User != nil {
			return wrapInvalidReg("backchannel_logout_uri must be an absolute URL without fragment or userinfo")
		}
		if p.Scheme != "https" && (!s.Cfg.OIDC.AllowPrivateNetworks || p.Scheme != "http") {
			return wrapInvalidReg("backchannel_logout_uri must use https")
		}
	}
	return nil
}

func singleHost(uris []string) bool {
	host := ""
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			return false
		}
		h := strings.ToLower(u.Hostname())
		if host == "" {
			host = h
		} else if host != h {
			return false
		}
	}
	return host != ""
}

var errOIDCDisabled = models.ErrOIDCDisabled

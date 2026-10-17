package as

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
)

var (
	ErrUserInfoInvalidToken      = errors.New("userinfo: invalid access token")
	ErrUserInfoInsufficientScope = errors.New("userinfo: access token lacks the openid scope")
)

// UserInfoRequest carries the presented access token and, for DPoP-bound tokens, the proof and its request.
type UserInfoRequest struct {
	AccessToken string
	DPoPProof   string
	HTTPMethod  string
	HTTPURL     string
}

// UserInfo returns the claims of the user behind an access token issued with the openid scope.
// profile and email follow the token's scopes.
func (s *Service) UserInfo(ctx context.Context, req UserInfoRequest) (map[string]any, error) {
	if !s.OIDCEnabled() {
		return nil, errOIDCDisabled
	}
	claims, ok := s.userInfoClaims(ctx, req.AccessToken)
	if !ok {
		return nil, ErrUserInfoInvalidToken
	}
	resp := s.introspectClaims(ctx, claims)
	if !resp.Active {
		return nil, ErrUserInfoInvalidToken
	}
	if resp.Cnf != nil && !s.userInfoProofOK(req, resp.Cnf.JKT) {
		return nil, ErrUserInfoInvalidToken
	}
	scope := strings.Fields(resp.Scope)
	if !hasScope(scope, ScopeOpenID) {
		return nil, ErrUserInfoInsufficientScope
	}
	var uid models.ULID
	if err := uid.UnmarshalText([]byte(resp.Sub)); err != nil || s.Users == nil {
		return nil, ErrUserInfoInvalidToken
	}
	user, err := s.Users.UserByID(ctx, uid)
	if err != nil || user == nil {
		return nil, ErrUserInfoInvalidToken
	}
	client, err := s.ResolveClient(ctx, resp.ClientID)
	if err != nil {
		return nil, ErrUserInfoInvalidToken
	}
	out := map[string]any{"sub": s.subjectFor(client, uid.String())}
	if hasScope(scope, ScopeProfile) {
		putIfSet(out, "name", firstNonEmpty(user.Name, user.DisplayName))
		putIfSet(out, "given_name", user.GivenName)
		putIfSet(out, "family_name", user.FamilyName)
		putIfSet(out, "picture", user.AvatarURL)
		if !user.UpdatedAt.IsZero() {
			out["updated_at"] = user.UpdatedAt.Unix()
		}
	}
	if hasScope(scope, ScopeEmail) {
		putIfSet(out, "email", user.Email)
		if user.Email != "" {
			out["email_verified"] = user.EmailVerifiedAt != nil
		}
	}
	return out, nil
}

func (s *Service) userInfoClaims(ctx context.Context, token string) (jwt.Claims, bool) {
	if token == "" {
		return jwt.Claims{}, false
	}
	if strings.Count(token, ".") == 2 {
		c, err := s.verifyAccessJWT(token, "", time.Now())
		return c, err == nil
	}
	return s.lookupOpaqueClaims(ctx, token)
}

func (s *Service) userInfoProofOK(req UserInfoRequest, jkt string) bool {
	if s.dpopSvc == nil || req.DPoPProof == "" {
		return false
	}
	proof, err := s.dpopSvc.Verify(req.DPoPProof, dpop.VerifyParams{
		Method:      req.HTTPMethod,
		URL:         req.HTTPURL,
		AccessToken: req.AccessToken,
		Now:         time.Now().UTC(),
	})
	return err == nil && jktEqual(proof.Thumbprint, jkt)
}

func putIfSet(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

package apitokens

import (
	"context"
	"errors"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"net/http"
	"time"
)

type principalOnlyKey struct{}

// requireBearerToken admits only a request authenticated by an API bearer
// token. A session cookie is refused with 403 so sessions keep using the
// session routes, and an invalid, expired, revoked or orphaned token gets 401.
func (s *Service) requireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := BearerToken(r); !ok {
			if c, err := r.Cookie(s.host.CookieName()); err == nil && c.Value != "" {
				httpx.WriteProblemJSON(w, http.StatusForbidden, "auth.bearer_required", "This route accepts an API bearer token only; sessions use "+s.host.PathPrefix()+"/tokens and "+s.host.PathPrefix()+"/me", "")
				return
			}
			httpx.WriteUnauthenticated(w, "auth.unauthenticated", "Missing credentials")
			return
		}
		p, ok := s.principalFromRequest(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalOnlyKey{}, p)))
	})
}

// currentTokenResponse is the self-description of a bearer token. It has no
// secret or hash field by construction.
type currentTokenResponse struct {
	ID         ULID       `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	AgentName  string     `json:"agentName,omitempty"`
	Abilities  []string   `json:"abilities"`
	OwnerID    ULID       `json:"ownerId"`
	OwnerKind  string     `json:"ownerKind"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

func (s *Service) handleTokenCurrent(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(principalOnlyKey{}).(*Principal)
	if p == nil || p.TokenID == nil {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "unauthenticated", "missing credentials")
		return
	}
	tok, err := s.store.APITokenByID(r.Context(), *p.TokenID)
	if errors.Is(err, models.ErrStorageNotFound) {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "unauthenticated", "invalid token")
		return
	}
	if err != nil {
		s.tokenInternalError(w, "load current token", err)
		return
	}
	abilities := p.Abilities
	if abilities == nil {
		abilities = []string{}
	}
	writeTokenJSON(w, http.StatusOK, currentTokenResponse{
		ID: tok.ID, Name: tok.Name, Kind: tok.Kind, AgentName: tok.AgentName, Abilities: abilities,
		OwnerID: tok.OwnerID, OwnerKind: tok.OwnerKind, CreatedAt: tok.CreatedAt,
		ExpiresAt: tok.ExpiresAt, LastUsedAt: tok.LastUsedAt,
	})
}

// handleTokenCurrentRevoke revokes the presented token and returns 204. The
// token is dead afterwards, so a repeat call fails authentication with 401.
func (s *Service) handleTokenCurrentRevoke(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(principalOnlyKey{}).(*Principal)
	if p == nil || p.TokenID == nil {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "unauthenticated", "missing credentials")
		return
	}
	if err := s.Revoke(r.Context(), *p.TokenID); err != nil {
		s.tokenInternalError(w, "revoke current token", err)
		return
	}
	s.host.RecordTokenRevoked(r.Context(), p.UserID, "api")
	w.WriteHeader(http.StatusNoContent)
}

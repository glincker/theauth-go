package theauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type principalOnlyKey struct{}

// requireBearerToken admits only a request authenticated by an API bearer
// token. A session cookie is refused with 403 so sessions keep using the
// session routes, and an invalid, expired, revoked or orphaned token gets 401.
func (a *TheAuth) requireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.apiSvc()
		if err != nil {
			writeProblemJSON(w, http.StatusNotFound, "apitokens.disabled", "API tokens are not enabled in Config", "")
			return
		}
		if _, ok := bearerToken(r); !ok {
			if c, err := r.Cookie(a.cookieName); err == nil && c.Value != "" {
				writeProblemJSON(w, http.StatusForbidden, "auth.bearer_required", "This route accepts an API bearer token only; sessions use "+a.pathPrefix+"/tokens and "+a.pathPrefix+"/me", "")
				return
			}
			writeUnauthenticated(w, "auth.unauthenticated", "Missing credentials")
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

func (a *TheAuth) handleTokenCurrent(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(principalOnlyKey{}).(*Principal)
	if p == nil || p.TokenID == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated", "missing credentials")
		return
	}
	tok, err := a.apiTokens.store.APITokenByID(r.Context(), *p.TokenID)
	if errors.Is(err, ErrStorageNotFound) {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated", "invalid token")
		return
	}
	if err != nil {
		a.tokenInternalError(w, "load current token", err)
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
func (a *TheAuth) handleTokenCurrentRevoke(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(principalOnlyKey{}).(*Principal)
	if p == nil || p.TokenID == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated", "missing credentials")
		return
	}
	if err := a.RevokeAPIToken(r.Context(), *p.TokenID); err != nil {
		a.tokenInternalError(w, "revoke current token", err)
		return
	}
	a.RecordTokenRevoked(r.Context(), p.UserID, "api")
	w.WriteHeader(http.StatusNoContent)
}

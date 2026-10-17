package account

// handlers_identitylink.go serves the /account/identities/* endpoints: OAuth link, password, merge
// and unlink. The session must be full; step-up is enforced by the service layer.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/admin"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/identitylink"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
)

// IdentityLinkService is the subset of identitylink.Service the handler needs, declared as an
// interface so tests can stub it.
type IdentityLinkService interface {
	LinkOAuthToCurrentUser(
		ctx context.Context,
		sessionToken, providerName, providerUserID string,
		accessTokenEnc, refreshTokenEnc []byte,
		expiresAt *time.Time,
		scope string,
	) error
	LinkPasswordToCurrentUser(ctx context.Context, sessionToken, password string) error
	MergeAccounts(ctx context.Context, sessionToken string, secondaryID models.ULID, input identitylink.MergeInput) error
	UnlinkOAuthProvider(ctx context.Context, sessionToken, provider string) error
}

// OAuthLinkInitiator provides the OAuth start step so the handler can begin
// a link flow. Implemented by the existing internal/oauth.Service via root.
type OAuthLinkInitiator interface {
	StartLink(ctx context.Context, providerName, sessionToken string) (authURL string, err error)
	CallbackLink(ctx context.Context, providerName, code, state, sessionToken string) error
}

// SessionTokenFromRequest extracts the raw session token from the cookie. Root supplies it, so this
// package need not know the cookie name.
type SessionTokenFromRequest func(r *http.Request) (string, bool)

// mountIdentityLink wires the five /account/identities/* routes. Called by
// Handler.Mount when an IdentityLinkService is configured.
func (h *Handler) mountIdentityLink(r chi.Router, requireAuth func(http.Handler) http.Handler) {
	if h.identityLink == nil {
		return
	}
	r.Route("/account/identities", func(r chi.Router) {
		r.Use(requireAuth)
		r.Post("/oauth", h.handleLinkOAuthBegin)
		r.Get("/oauth/callback", h.handleLinkOAuthCallback)
		r.Post("/password", h.handleLinkPassword)
		r.Post("/merge", h.handleMerge)
		r.Delete("/{provider}", h.handleUnlinkProvider)
	})
}

// handleLinkOAuthBegin starts an OAuth link flow and returns the provider authorization URL. The
// session cookie must be present, so the callback binds the result to the right user.
func (h *Handler) handleLinkOAuthBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil || body.Provider == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "provider required", "")
		return
	}

	if h.oauthLinkInitiator == nil {
		admin.Write(w, http.StatusNotImplemented, "not_implemented", "OAuth link not configured", "")
		return
	}

	sessToken, ok := h.sessionToken(r)
	if !ok {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}

	authURL, err := h.oauthLinkInitiator.StartLink(r.Context(), body.Provider, sessToken)
	if err != nil {
		if errors.Is(err, models.ErrStepUpRequired) {
			admin.Write(w, http.StatusForbidden, models.CodeStepUpRequired, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"authorizationUrl": authURL})
}

// handleLinkOAuthCallback completes the OAuth link flow: the code is exchanged and the identity
// linked to the current user.
func (h *Handler) handleLinkOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if provider == "" || code == "" || state == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "provider, code, state required", "")
		return
	}

	if h.oauthLinkInitiator == nil {
		admin.Write(w, http.StatusNotImplemented, "not_implemented", "OAuth link not configured", "")
		return
	}

	sessToken, ok := h.sessionToken(r)
	if !ok {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}

	err := h.oauthLinkInitiator.CallbackLink(r.Context(), provider, code, state, sessToken)
	if err != nil {
		var conflict *models.IdentityConflictError
		if errors.As(err, &conflict) {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{
				"code":              models.CodeIdentityConflict,
				"message":           err.Error(),
				"conflictingUserId": conflict.ConflictingUserID.String(),
			})
			return
		}
		if errors.Is(err, models.ErrStepUpRequired) {
			admin.Write(w, http.StatusForbidden, models.CodeStepUpRequired, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"linked": true})
}

// handleLinkPassword adds email+password as a backup method.
func (h *Handler) handleLinkPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil || body.Password == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "password required", "")
		return
	}

	sessToken, ok := h.sessionToken(r)
	if !ok {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}

	if err := h.identityLink.LinkPasswordToCurrentUser(r.Context(), sessToken, body.Password); err != nil {
		if errors.Is(err, models.ErrStepUpRequired) {
			admin.Write(w, http.StatusForbidden, models.CodeStepUpRequired, err.Error(), "")
			return
		}
		var te *models.TheAuthError
		if errors.As(err, &te) {
			httpx.ErrToHTTP(w, err)
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"linked": true})
}

// handleMerge destructively merges a secondary user into the authenticated
// primary user. Requires explicit caller intent (secondaryUserId in body).
func (h *Handler) handleMerge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SecondaryUserID string `json:"secondaryUserId"`
		Reason          string `json:"reason,omitempty"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil || body.SecondaryUserID == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "secondaryUserId required", "")
		return
	}

	secondaryID, err := ulid.Parse(body.SecondaryUserID)
	if err != nil {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "invalid secondaryUserId", "")
		return
	}

	sessToken, ok := h.sessionToken(r)
	if !ok {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}

	if err := h.identityLink.MergeAccounts(
		r.Context(),
		sessToken,
		secondaryID,
		identitylink.MergeInput{AuditReason: body.Reason},
	); err != nil {
		if errors.Is(err, models.ErrStepUpRequired) {
			admin.Write(w, http.StatusForbidden, models.CodeStepUpRequired, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusInternalServerError, admin.CodeInternal, err.Error(), "")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"merged": true})
}

// handleUnlinkProvider removes a named OAuth provider from the user's
// account, refusing if it is the last auth method.
func (h *Handler) handleUnlinkProvider(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, "provider required", "")
		return
	}

	sessToken, ok := h.sessionToken(r)
	if !ok {
		admin.Write(w, http.StatusUnauthorized, admin.CodeUnauthorized, "no session", "")
		return
	}

	if err := h.identityLink.UnlinkOAuthProvider(r.Context(), sessToken, provider); err != nil {
		if errors.Is(err, models.ErrStepUpRequired) {
			admin.Write(w, http.StatusForbidden, models.CodeStepUpRequired, err.Error(), "")
			return
		}
		if errors.Is(err, models.ErrLastAuthMethod) {
			admin.Write(w, http.StatusConflict, models.CodeLastAuthMethod, err.Error(), "")
			return
		}
		admin.Write(w, http.StatusBadRequest, admin.CodeValidationInvalid, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

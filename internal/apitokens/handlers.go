package apitokens

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/go-chi/chi/v5"
	oulid "github.com/oklog/ulid/v2"
)

// mountAPITokens registers /auth/tokens. List, mint and revoke-by-id need a
// full session: a token cannot mint or revoke tokens, which blocks escalation
// chains. Only /tokens/current is bearer-only and touches the caller's own record.
func (s *Service) MountTokens(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.Route("/tokens", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(ipLimit, s.requireBearerToken)
			r.Get("/current", s.handleTokenCurrent)
			r.Delete("/current", s.handleTokenCurrentRevoke)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.host.RequireAuth())
			r.With(ipLimit).Post("/", s.handleTokenCreate)
			r.Get("/", s.handleTokenList)
			r.Delete("/{id}", s.handleTokenRevoke)
		})
	})
}

type tokenCreateBody struct {
	Name           string   `json:"name"`
	Abilities      []string `json:"abilities"`
	ExpiresIn      int64    `json:"expires_in"`
	Kind           string   `json:"kind"`
	AgentName      string   `json:"agent_name"`
	ServiceAccount bool     `json:"service_account"`
	OwnerID        string   `json:"owner_id"`
}

type tokenCreateResponse struct {
	Token string `json:"token"`
	APIToken
}

func writeTokenJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Service) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := s.host.UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var body tokenCreateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	held, err := s.UserAbilities(r.Context(), user)
	if err != nil {
		s.tokenInternalError(w, "resolve grantor abilities", err)
		return
	}
	in := MintAPITokenInput{OwnerID: user.ID, OwnerKind: OwnerKindUser, Name: body.Name, Abilities: body.Abilities, TTL: time.Duration(body.ExpiresIn) * time.Second, Kind: body.Kind, AgentName: body.AgentName}
	if body.ServiceAccount {
		admin, err := s.IsAdmin(r.Context(), user)
		if err != nil {
			s.tokenInternalError(w, "admin check", err)
			return
		}
		if !admin {
			httpx.WriteJSONError(w, http.StatusForbidden, "forbidden", "only an admin can mint service account tokens")
			return
		}
		in.OwnerKind = OwnerKindServiceAccount
		in.OwnerID = ulid.New()
		if body.OwnerID != "" {
			id, err := oulid.ParseStrict(body.OwnerID)
			if err != nil {
				httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_owner_id", "owner_id is not a valid ID")
				return
			}
			in.OwnerID = id
		}
	}
	if err := s.validateAbilities(in.Abilities, false); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_abilities", err.Error())
		return
	}
	if len(clampAbilities(in.Abilities, held)) != len(in.Abilities) {
		httpx.WriteJSONError(w, http.StatusForbidden, "ability_not_held", ErrAbilityNotHeld.Error())
		return
	}
	raw, tok, err := s.Mint(r.Context(), in)
	switch {
	case errors.Is(err, ErrTokenTTLInvalid):
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_expiry", err.Error())
	case err != nil:
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_token", err.Error())
	default:
		writeTokenJSON(w, http.StatusCreated, tokenCreateResponse{Token: raw, APIToken: tok})
	}
}

func (s *Service) handleTokenList(w http.ResponseWriter, r *http.Request) {
	user, _ := s.host.UserFromContext(r.Context())
	q := r.URL.Query()
	var (
		toks []APIToken
		err  error
	)
	if q.Get("all") == "true" || q.Get("owner_id") != "" {
		admin, aerr := s.IsAdmin(r.Context(), user)
		if aerr != nil {
			s.tokenInternalError(w, "admin check", aerr)
			return
		}
		if !admin {
			httpx.WriteJSONError(w, http.StatusForbidden, "forbidden", "admin only")
			return
		}
		if q.Get("owner_id") != "" {
			id, perr := oulid.ParseStrict(q.Get("owner_id"))
			if perr != nil {
				httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_owner_id", "owner_id is not a valid ID")
				return
			}
			toks, err = s.store.APITokensByOwner(r.Context(), id)
		} else {
			toks, err = s.store.ListAPITokens(r.Context())
		}
	} else {
		toks, err = s.store.APITokensByOwner(r.Context(), user.ID)
	}
	if err != nil {
		s.tokenInternalError(w, "list tokens", err)
		return
	}
	if toks == nil {
		toks = []APIToken{}
	}
	writeTokenJSON(w, http.StatusOK, map[string]any{"tokens": toks})
}

func (s *Service) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	user, _ := s.host.UserFromContext(r.Context())
	id, err := oulid.ParseStrict(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSONError(w, http.StatusNotFound, "not_found", "token not found")
		return
	}
	tok, err := s.store.APITokenByID(r.Context(), id)
	if errors.Is(err, models.ErrStorageNotFound) {
		httpx.WriteJSONError(w, http.StatusNotFound, "not_found", "token not found")
		return
	}
	if err != nil {
		s.tokenInternalError(w, "load token", err)
		return
	}
	if tok.OwnerID != user.ID {
		admin, aerr := s.IsAdmin(r.Context(), user)
		if aerr != nil {
			s.tokenInternalError(w, "admin check", aerr)
			return
		}
		if !admin {
			httpx.WriteJSONError(w, http.StatusNotFound, "not_found", "token not found")
			return
		}
	}
	if err := s.Revoke(r.Context(), id); err != nil {
		s.tokenInternalError(w, "revoke token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) tokenInternalError(w http.ResponseWriter, what string, err error) {
	slog.Error("theauth: api tokens: "+what+" failed", "err", err.Error())
	httpx.WriteJSONError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

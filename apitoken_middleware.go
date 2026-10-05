package theauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// PrincipalKind says how a request was authenticated.
type PrincipalKind string

// Principal kinds.
const (
	PrincipalSession PrincipalKind = "session"
	PrincipalToken   PrincipalKind = "token"
)

// Principal is the authenticated caller of a request: a signed-in user or an
// API token acting for its owner.
type Principal struct {
	Kind PrincipalKind
	// UserID is the user, or the service account ID for a service account token.
	UserID    ULID
	OwnerKind string
	TokenID   *ULID
	// Abilities are the effective abilities for this request.
	Abilities []string
	user      *User
}

// Has reports whether the principal holds the ability, directly or through root.
func (p Principal) Has(ability string) bool { return holdsAbility(p.Abilities, ability) }

type principalCtxKey struct{}

// PrincipalFromContext returns the Principal attached by RequireAbility.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return p, ok
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// RequireAbility accepts either a full session or an API bearer token and
// rejects callers that do not currently hold ability. A presented bearer
// token never falls back to the cookie. Needs Config.APITokens.
func (a *TheAuth) RequireAbility(ability string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, err := a.apiSvc()
			if err != nil {
				writeProblemJSON(w, http.StatusInternalServerError, "apitokens.disabled", "API tokens are not enabled in Config", "")
				return
			}
			p, ok := s.principalFromRequest(w, r)
			if !ok {
				return
			}
			if !p.Has(ability) {
				writeProblemJSON(w, http.StatusForbidden, "auth.forbidden", "Missing required ability: "+ability, "")
				return
			}
			ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
			if p.user != nil {
				ctx = context.WithValue(ctx, userKey, p.user)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *apiTokenService) principalFromRequest(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	if raw, ok := bearerToken(r); ok {
		p, err := s.authenticate(r.Context(), raw)
		if err != nil {
			if !errors.Is(err, ErrAPITokenInvalid) {
				slog.Error("theauth: API token authentication failed", "err", err.Error())
				writeProblemJSON(w, http.StatusInternalServerError, "auth.internal_error", "Authentication failed", "")
				return nil, false
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="theauth", error="invalid_token"`)
			writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "Invalid API token", "")
			return nil, false
		}
		return p, true
	}
	c, err := r.Cookie(s.a.cookieName)
	if err != nil || c.Value == "" {
		writeUnauthenticated(w, "auth.unauthenticated", "Missing credentials")
		return nil, false
	}
	return s.sessionPrincipal(w, r, c.Value)
}

func (s *apiTokenService) sessionPrincipal(w http.ResponseWriter, r *http.Request, token string) (*Principal, bool) {
	sess, user, err := s.a.validateSession(r.Context(), token)
	if err != nil {
		writeUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
		return nil, false
	}
	if sess.AuthLevel != "" && sess.AuthLevel != AuthLevelFull {
		writeUnauthenticated(w, "auth.step_up_required", "Session requires second-factor verification")
		return nil, false
	}
	abilities, err := s.userAbilities(r.Context(), user)
	if err != nil {
		slog.Error("theauth: resolve session abilities failed", "err", err.Error())
		writeProblemJSON(w, http.StatusInternalServerError, "auth.internal_error", "Authentication failed", "")
		return nil, false
	}
	return &Principal{Kind: PrincipalSession, UserID: user.ID, OwnerKind: OwnerKindUser, Abilities: abilities, user: user}, true
}

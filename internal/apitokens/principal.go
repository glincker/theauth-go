package apitokens

import (
	"context"
	"errors"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
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
	// TokenKind is the API token kind, empty for sessions.
	TokenKind string
	// AgentName names the agent behind an agent token.
	AgentName string
	// DelegatedBy is the human an agent token acts for.
	DelegatedBy *ULID
	user        *User
}

// Actor is one link of an actor chain.
type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Actor kinds.
const (
	ActorKindUser  = "user"
	ActorKindAgent = "agent"
)

// ActorChain lists who is acting, outermost first: the human, then the agent
// acting for them. A plain user or personal token yields just the user.
func (p Principal) ActorChain() []Actor {
	chain := []Actor{{Kind: ActorKindUser, ID: p.UserID.String()}}
	if p.AgentName != "" {
		chain = append(chain, Actor{Kind: ActorKindAgent, ID: tokenIDString(p.TokenID), Name: p.AgentName})
	}
	return chain
}

func tokenIDString(id *ULID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// Has reports whether the principal holds the ability, directly or through root.
func (p Principal) Has(ability string) bool { return holdsAbility(p.Abilities, ability) }

type principalCtxKey struct{}

func (s *Service) withPrincipal(ctx context.Context, p *Principal) context.Context {
	ctx = context.WithValue(ctx, principalCtxKey{}, p)
	if p.user != nil {
		ctx = s.host.WithUser(ctx, p.user)
	}
	return ctx
}

// PrincipalFromContext returns the Principal attached by RequireAbility.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return p, ok
}

// BearerToken extracts a bearer secret from the Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// RequireAbility accepts either a full session or an API bearer token and
// rejects callers that do not currently hold ability. A presented bearer
// token never falls back to the cookie. Needs Config.APITokens.
func (s *Service) RequireAbility(ability string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := s.principalFromRequest(w, r)
			if !ok {
				return
			}
			if !p.Has(ability) {
				httpx.WriteProblemJSON(w, http.StatusForbidden, "auth.forbidden", "Missing required ability: "+ability, "")
				return
			}
			next.ServeHTTP(w, r.WithContext(s.withPrincipal(r.Context(), p)))
		})
	}
}

func (s *Service) principalFromRequest(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	if raw, ok := BearerToken(r); ok {
		p, err := s.Authenticate(r.Context(), raw)
		if err != nil {
			if !errors.Is(err, ErrAPITokenInvalid) {
				slog.Error("theauth: API token authentication failed", "err", err.Error())
				httpx.WriteProblemJSON(w, http.StatusInternalServerError, "auth.internal_error", "Authentication failed", "")
				return nil, false
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="theauth", error="invalid_token"`)
			httpx.WriteProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "Invalid API token", "")
			return nil, false
		}
		return p, true
	}
	c, err := r.Cookie(s.host.CookieName())
	if err != nil || c.Value == "" {
		httpx.WriteUnauthenticated(w, "auth.unauthenticated", "Missing credentials")
		return nil, false
	}
	return s.sessionPrincipal(w, r, c.Value)
}

func (s *Service) sessionPrincipal(w http.ResponseWriter, r *http.Request, token string) (*Principal, bool) {
	sess, user, err := s.host.ValidateSession(r.Context(), token)
	if err != nil {
		httpx.WriteUnauthenticated(w, "auth.unauthenticated", "Missing or invalid session")
		return nil, false
	}
	if sess.AuthLevel != "" && sess.AuthLevel != models.AuthLevelFull {
		httpx.WriteUnauthenticated(w, "auth.step_up_required", "Session requires second-factor verification")
		return nil, false
	}
	abilities, err := s.UserAbilities(r.Context(), user)
	if err != nil {
		slog.Error("theauth: resolve session abilities failed", "err", err.Error())
		httpx.WriteProblemJSON(w, http.StatusInternalServerError, "auth.internal_error", "Authentication failed", "")
		return nil, false
	}
	return &Principal{Kind: PrincipalSession, UserID: user.ID, OwnerKind: OwnerKindUser, Abilities: abilities, user: user}, true
}

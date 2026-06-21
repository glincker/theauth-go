package theauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// handlers_oauth_server.go: chi handlers for the v2.0 (phase 1 + 2) OAuth 2.1
// authorization server. Mounted from Mount when Config.AuthorizationServer is
// non-nil. Routes:
//
//   GET  /.well-known/oauth-authorization-server
//   GET  /oauth/authorize
//   POST /oauth/token
//   POST /oauth/revoke
//   POST /oauth/introspect
//   POST /oauth/register
//   GET  /oauth/jwks

func (a *TheAuth) mountAS(r chi.Router) {
	if a.as == nil {
		return
	}
	r.Get("/.well-known/oauth-authorization-server", a.handleASMetadata)
	// RFC 9728 OAuth 2.0 Protected Resource Metadata. Two flavours: the bare
	// path returns metadata for the first configured resource (most common
	// single-resource deployment); the suffixed path returns metadata for an
	// arbitrary registered resource so MCP clients can discover any AS that
	// fronts multiple resources.
	r.Get("/.well-known/oauth-protected-resource", a.handleProtectedResourceMetadata)
	r.Get("/.well-known/oauth-protected-resource/*", a.handleProtectedResourceMetadata)
	r.Get("/oauth/jwks", a.handleJWKS)
	r.With(a.Authn()).Get("/oauth/authorize", a.handleAuthorize)
	r.Post("/oauth/token", a.handleToken)
	r.Post("/oauth/revoke", a.handleRevoke)
	r.Post("/oauth/introspect", a.handleIntrospect)
	r.Post("/oauth/register", a.handleRegister)
}

// ---------- discovery ----------

func (a *TheAuth) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	doc, err := a.ASMetadataDoc()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (a *TheAuth) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if a.as == nil {
		http.Error(w, "not configured", http.StatusNotFound)
		return
	}
	resourceID := chi.URLParam(r, "*")
	// Resolve the resource identifier. The wildcard segment carries the path
	// portion of the resource URI when the AS hosts multiple resources; for
	// the bare /.well-known/oauth-protected-resource path we fall back to
	// the first configured resource so the most common deployment (one
	// resource per AS) just works without configuration.
	var ident string
	switch {
	case resourceID != "":
		// Reconstruct the full resource URI from the AS Issuer host plus the
		// wildcard tail. The AS Issuer scheme + host is canonical; tail must
		// match the configured Identifier's path component.
		ident = a.as.cfg.Issuer + "/" + strings.TrimPrefix(resourceID, "/")
		if _, ok := a.resourceByIdentifier(ident); !ok {
			// Try the wildcard tail as a full URL too (covers cases where
			// the resource lives on a different host than the AS).
			if _, ok := a.resourceByIdentifier(strings.TrimPrefix(resourceID, "/")); ok {
				ident = strings.TrimPrefix(resourceID, "/")
			}
		}
	default:
		if len(a.as.cfg.Resources) == 0 {
			http.Error(w, "no resources configured", http.StatusNotFound)
			return
		}
		ident = a.as.cfg.Resources[0].Identifier
	}
	doc, err := a.ProtectedResourceMetadataDoc(ident)
	if err != nil {
		http.Error(w, "unknown resource", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (a *TheAuth) handleJWKS(w http.ResponseWriter, r *http.Request) {
	body, err := a.renderJWKSDoc()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

// ---------- authorize ----------

func (a *TheAuth) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               scopeSplit(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Resource:            q.Get("resource"),
		Nonce:               q.Get("nonce"),
	}
	user, _ := UserFromContext(r.Context())
	res, err := a.StartAuthorize(r.Context(), req, user)
	if err != nil {
		if IsLoginRequired(err) {
			next := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, a.as.cfg.LoginURL+"?next="+next, http.StatusFound)
			return
		}
		writeAuthorizeError(w, r, req, err)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

func writeAuthorizeError(w http.ResponseWriter, r *http.Request, req AuthorizeRequest, err error) {
	code := mapOAuthErrorCode(err)
	// When a redirect_uri is available and the error is not a client / target
	// validation failure, OAuth 2.1 mandates redirecting back with the error
	// query parameters. Errors detected before client validation (invalid
	// client_id or invalid resource) are surfaced inline as 400 JSON so we do
	// not leak state to an unverified redirect target.
	if req.RedirectURI != "" && code != OAuthErrInvalidRequest && code != OAuthErrInvalidTarget {
		u, perr := url.Parse(req.RedirectURI)
		if perr == nil {
			qq := u.Query()
			qq.Set("error", code)
			if req.State != "" {
				qq.Set("state", req.State)
			}
			u.RawQuery = qq.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	writeOAuthError(w, http.StatusBadRequest, code, err.Error())
}

// ---------- token ----------

func (a *TheAuth) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, OAuthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case GrantTypeAuthorizationCode:
		req := TokenRequest{
			GrantType:    grantType,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Code:         r.PostFormValue("code"),
			CodeVerifier: r.PostFormValue("code_verifier"),
			RedirectURI:  r.PostFormValue("redirect_uri"),
		}
		resp, err := a.ExchangeAuthorizationCode(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case GrantTypeRefreshToken:
		req := TokenRequest{
			GrantType:    grantType,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RefreshToken: r.PostFormValue("refresh_token"),
			Resource:     r.PostFormValue("resource"),
			Scope:        scopeSplit(r.PostFormValue("scope")),
		}
		resp, err := a.RefreshAccessToken(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case GrantTypeClientCredentials:
		req := TokenRequest{
			GrantType:    grantType,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     r.PostFormValue("resource"),
			Scope:        scopeSplit(r.PostFormValue("scope")),
		}
		resp, err := a.ClientCredentialsToken(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case GrantTypeTokenExchange:
		req := TokenExchangeRequest{
			ClientID:           clientID,
			ClientSecret:       clientSecret,
			SubjectToken:       r.PostFormValue("subject_token"),
			SubjectTokenType:   r.PostFormValue("subject_token_type"),
			ActorToken:         r.PostFormValue("actor_token"),
			ActorTokenType:     r.PostFormValue("actor_token_type"),
			RequestedTokenType: r.PostFormValue("requested_token_type"),
			Resource:           r.PostFormValue("resource"),
			Audience:           r.PostFormValue("audience"),
			Scope:              scopeSplit(r.PostFormValue("scope")),
		}
		resp, err := a.ExchangeToken(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	default:
		writeOAuthError(w, http.StatusBadRequest, OAuthErrUnsupportedGrantType, "grant_type not supported")
	}
}

func writeTokenJSON(w http.ResponseWriter, resp TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, err error) {
	code := mapOAuthErrorCode(err)
	status := http.StatusBadRequest
	if code == OAuthErrInvalidClient {
		status = http.StatusUnauthorized
	}
	writeOAuthError(w, status, code, err.Error())
}

// ---------- revoke ----------

func (a *TheAuth) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, OAuthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	token := r.PostFormValue("token")
	hint := r.PostFormValue("token_type_hint")
	if err := a.RevokeToken(r.Context(), token, hint, clientID, clientSecret); err != nil {
		if errors.Is(err, ErrOAuthInvalidClient) {
			writeOAuthError(w, http.StatusUnauthorized, OAuthErrInvalidClient, "client authentication failed")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, OAuthErrInvalidRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------- introspect ----------

func (a *TheAuth) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, OAuthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	token := r.PostFormValue("token")
	aud := r.PostFormValue("resource")
	_, body, err := a.IntrospectToken(r.Context(), token, clientID, clientSecret, aud)
	if err != nil {
		if errors.Is(err, ErrOAuthInvalidClient) {
			writeOAuthError(w, http.StatusUnauthorized, OAuthErrInvalidClient, "client authentication failed")
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, OAuthErrServerError, err.Error())
		return
	}
	maxAge := int(a.as.cfg.IntrospectionCacheTTL.Seconds())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(maxAge))
	_, _ = w.Write(body)
}

// ---------- register ----------

func (a *TheAuth) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON")
		return
	}
	anonymous := true
	if authz := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		anonymous = false
	}
	resp, err := a.RegisterClient(r.Context(), req, anonymous)
	if err != nil {
		if errors.Is(err, ErrOAuthRegistrationDenied) {
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "anonymous registration not permitted")
			return
		}
		var te *TheAuthError
		if errors.As(err, &te) {
			writeOAuthError(w, http.StatusBadRequest, te.Code, te.Message)
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, OAuthErrServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------- helpers ----------

// parseClientCredentials extracts client_id / client_secret from the request.
// HTTP Basic auth takes precedence per RFC 6749 section 2.3.1; absent that,
// fall back to client_id / client_secret in the form body.
func parseClientCredentials(r *http.Request) (string, string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(raw), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

// writeOAuthError emits the standard OAuth error JSON body shape.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: code, ErrorDescription: description})
}

// mapOAuthErrorCode maps internal sentinels to wire error codes. The
// phase 3 + 4 additions map agent + delegation failures to access_denied
// (RFC 6749 section 5.2) and chain depth / subject token failures to
// invalid_request so callers can distinguish a malformed exchange from a
// genuinely revoked grant.
func mapOAuthErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrOAuthInvalidRequest),
		errors.Is(err, ErrChainDepthExceeded),
		errors.Is(err, ErrSubjectTokenInvalid),
		errors.Is(err, ErrActorTokenInvalid):
		return OAuthErrInvalidRequest
	case errors.Is(err, ErrOAuthInvalidClient):
		return OAuthErrInvalidClient
	case errors.Is(err, ErrOAuthInvalidGrant), errors.Is(err, ErrOAuthRedirectURIMismatch), errors.Is(err, ErrOAuthPKCEMismatch):
		return OAuthErrInvalidGrant
	case errors.Is(err, ErrOAuthInvalidScope):
		return OAuthErrInvalidScope
	case errors.Is(err, ErrOAuthUnsupportedGrantType):
		return OAuthErrUnsupportedGrantType
	case errors.Is(err, ErrOAuthUnsupportedResponseType):
		return OAuthErrUnsupportedResponseType
	case errors.Is(err, ErrOAuthInvalidResource):
		return OAuthErrInvalidTarget
	case errors.Is(err, ErrAgentInactive),
		errors.Is(err, ErrDelegationNotFound),
		errors.Is(err, ErrDelegationRevoked):
		return OAuthErrAccessDenied
	}
	return OAuthErrServerError
}

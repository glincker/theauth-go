// Package handlers exposes the OAuth 2.1 + MCP authorization server
// HTTP endpoints. Routes:
//
//	GET  /.well-known/oauth-authorization-server
//	GET  /.well-known/oauth-protected-resource
//	GET  /.well-known/oauth-protected-resource/*
//	GET  /oauth/jwks
//	GET  /oauth/authorize          (auth-gated)
//	POST /oauth/token
//	POST /oauth/revoke
//	POST /oauth/introspect
//	POST /oauth/register           (per-IP rate-limited when cap > 0)
//
// Extracted from root handlers_oauth_server.go in PR F of the 2026-06
// architecture reorg. The root *theauth.TheAuth constructs a Handler
// here and Mount is invoked from the thin mountAS forwarder. The
// scopeSplit helper that used to live in root scope_helpers.go now
// lives in internal/as.scopeSplit (already present from PR C); this
// package re-uses it via the unexported package-level function below.
package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/go-chi/chi/v5"
)

// Handler owns the AS HTTP surface.
type Handler struct {
	svc          *internalas.Service
	userFromCtx  func(r *http.Request) (*models.User, bool)
	bearerHashes [][32]byte
}

// New constructs a Handler. The userFromCtx shim pulls the
// authenticated user out of the request context after the Authn
// middleware has run on /oauth/authorize. The bearerHashes slice is
// the pre-computed sha256 digest set of operator-supplied DCR
// registration tokens (Config.AuthorizationServer.RegistrationTokens);
// nil or empty means no bearer-gated registration is permitted.
func New(svc *internalas.Service, userFromCtx func(r *http.Request) (*models.User, bool), bearerHashes [][32]byte) *Handler {
	return &Handler{svc: svc, userFromCtx: userFromCtx, bearerHashes: bearerHashes}
}

// Mount registers the AS routes onto r. The caller supplies authn
// (for /oauth/authorize) and a rateLimit middleware factory that
// returns the per-IP cap for /oauth/register; rateLimit may be nil
// when the operator opted out of the cap.
func (h *Handler) Mount(r chi.Router, authn func(http.Handler) http.Handler, registerLimit func(http.Handler) http.Handler) {
	r.Get("/.well-known/oauth-authorization-server", h.handleASMetadata)
	r.Get("/.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	r.Get("/.well-known/oauth-protected-resource/*", h.handleProtectedResourceMetadata)
	r.Get("/oauth/jwks", h.handleJWKS)
	r.With(authn).Get("/oauth/authorize", h.handleAuthorize)
	r.Post("/oauth/token", h.handleToken)
	r.Post("/oauth/revoke", h.handleRevoke)
	r.Post("/oauth/introspect", h.handleIntrospect)
	if registerLimit != nil {
		r.With(registerLimit).Post("/oauth/register", h.handleRegister)
	} else {
		r.Post("/oauth/register", h.handleRegister)
	}
	// PAR (RFC 9126): POST /oauth/par is registered only when PAR is enabled
	// and the backend supports it. Doing the check here instead of in the
	// handler keeps the router clean: unknown routes get a 405 rather than a
	// runtime error body.
	if h.svc.IsPAREnabled() {
		r.Post("/oauth/par", h.handlePAR)
	}
}

// ---------- discovery ----------

func (h *Handler) handleASMetadata(w http.ResponseWriter, _ *http.Request) {
	doc, err := h.svc.ASMetadataDoc()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (h *Handler) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	resourceID := chi.URLParam(r, "*")
	var ident string
	switch {
	case resourceID != "":
		ident = h.svc.Cfg.Issuer + "/" + strings.TrimPrefix(resourceID, "/")
		if _, ok := h.svc.ResourceByIdentifier(ident); !ok {
			if _, ok := h.svc.ResourceByIdentifier(strings.TrimPrefix(resourceID, "/")); ok {
				ident = strings.TrimPrefix(resourceID, "/")
			}
		}
	default:
		if len(h.svc.Cfg.Resources) == 0 {
			http.Error(w, "no resources configured", http.StatusNotFound)
			return
		}
		ident = h.svc.Cfg.Resources[0].Identifier
	}
	doc, err := h.svc.ProtectedResourceMetadataDoc(ident)
	if err != nil {
		http.Error(w, "unknown resource", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (h *Handler) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	body, err := h.svc.RenderJWKSDoc()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

// ---------- authorize ----------

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	requestURI := q.Get("request_uri")
	requestObject := q.Get("request")

	// RFC 9101: request and request_uri cannot coexist.
	if requestURI != "" && requestObject != "" {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "request and request_uri are mutually exclusive")
		return
	}

	var req internalas.AuthorizeRequest

	switch {
	case requestURI != "":
		// PAR path: consume the pushed request.
		// RFC 9126 section 3: when request_uri is present, inline params
		// (other than client_id) MUST be absent.
		if hasInlineAuthorizeParams(q, clientID) {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "inline params must not accompany request_uri")
			return
		}
		// RequirePAR check happens implicitly: if PAR is required and the
		// client sent inline params, the hasInlineAuthorizeParams guard
		// above catches it. A request_uri path always passes.
		var err error
		req, err = h.svc.ConsumePushedRequest(r.Context(), requestURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "invalid or expired request_uri")
			return
		}
		// Bind client_id from query (MUST match inner client_id).
		if clientID != "" && req.ClientID != clientID {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "client_id mismatch with request_uri")
			return
		}

	case requestObject != "":
		// JAR path: parse and verify the request JWT.
		// RFC 9101 section 5: outer params (except client_id) are ignored.
		client, err := h.svc.ResolveClient(r.Context(), clientID)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "unknown client")
			return
		}
		req, err = h.svc.ParseRequestObject(r.Context(), requestObject, clientID, h.svc.Cfg.Issuer, client)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
			return
		}
		// Outer client_id is authoritative when the inner JWT omits it.
		if req.ClientID == "" {
			req.ClientID = clientID
		}

	default:
		// Classic inline-param path.
		// If RequirePAR is on, reject.
		if h.svc.Cfg.PAR != nil && h.svc.Cfg.PAR.RequirePAR {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "pushed_authorization_request_required")
			return
		}
		// If RequireJAR is on, reject.
		if h.svc.Cfg.JAR != nil && h.svc.Cfg.JAR.RequireJAR {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "request_object_required")
			return
		}
		req = internalas.AuthorizeRequest{
			ClientID:            clientID,
			RedirectURI:         q.Get("redirect_uri"),
			ResponseType:        q.Get("response_type"),
			Scope:               scopeSplit(q.Get("scope")),
			State:               q.Get("state"),
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			Resource:            q.Get("resource"),
			Nonce:               q.Get("nonce"),
		}
	}

	user, _ := h.userFromCtx(r)
	res, err := h.svc.StartAuthorize(r.Context(), req, user)
	if err != nil {
		if internalas.IsLoginRequired(err) {
			next := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, h.svc.Cfg.LoginURL+"?next="+next, http.StatusFound)
			return
		}
		writeAuthorizeError(w, r, req, err)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

// hasInlineAuthorizeParams returns true when the query string contains any
// authorization parameter other than client_id and request_uri. Used to
// enforce RFC 9126 section 3's prohibition on mixing request_uri with inline
// params.
func hasInlineAuthorizeParams(q url.Values, clientID string) bool {
	check := []string{
		"response_type", "redirect_uri", "scope", "state",
		"code_challenge", "code_challenge_method", "resource", "nonce",
	}
	for _, k := range check {
		if q.Get(k) != "" {
			return true
		}
	}
	return false
}

// ---------- PAR ----------

func (h *Handler) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, _ := parseClientCredentials(r)

	// JAR support inside PAR: if a "request" param is present, extract
	// the authorization request from the JWT (RFC 9101 inside RFC 9126).
	var req internalas.AuthorizeRequest
	if ro := r.PostFormValue("request"); ro != "" {
		client, err := h.svc.ResolveClient(r.Context(), clientID)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "unknown client")
			return
		}
		req, err = h.svc.ParseRequestObject(r.Context(), ro, clientID, h.svc.Cfg.Issuer, client)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
			return
		}
		if req.ClientID == "" {
			req.ClientID = clientID
		}
	} else {
		req = internalas.AuthorizeRequest{
			ClientID:            clientID,
			RedirectURI:         r.PostFormValue("redirect_uri"),
			ResponseType:        r.PostFormValue("response_type"),
			Scope:               scopeSplit(r.PostFormValue("scope")),
			State:               r.PostFormValue("state"),
			CodeChallenge:       r.PostFormValue("code_challenge"),
			CodeChallengeMethod: r.PostFormValue("code_challenge_method"),
			Resource:            r.PostFormValue("resource"),
			Nonce:               r.PostFormValue("nonce"),
		}
	}

	resp, err := h.svc.PushAuthorize(r.Context(), req)
	if err != nil {
		code := mapOAuthErrorCode(err)
		status := http.StatusBadRequest
		if code == oauthErrInvalidClient {
			status = http.StatusUnauthorized
		}
		writeOAuthError(w, status, code, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeAuthorizeError(w http.ResponseWriter, r *http.Request, req internalas.AuthorizeRequest, err error) {
	code := mapOAuthErrorCode(err)
	if req.RedirectURI != "" && code != oauthErrInvalidRequest && code != oauthErrInvalidTarget {
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

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	grantType := r.PostFormValue("grant_type")
	// RFC 7523 section 2.2 client_assertion fields.
	clientAssertionType := r.PostFormValue("client_assertion_type")
	clientAssertion := r.PostFormValue("client_assertion")
	// When client_id is absent but client_assertion is present, extract the
	// client_id from the assertion iss claim (RFC 7523 requires iss = client_id).
	if clientID == "" && clientAssertion != "" {
		clientID = jwtPeekIss(clientAssertion)
	}
	// DPoP proof comes in via the DPoP header (RFC 9449 section 4). The
	// HTTPMethod / HTTPURL are passed through to the verifier so it can
	// match against the htm / htu claims; the verifier strips fragment +
	// query string from htu so it is fine to pass the full URL here.
	dpopHeader := r.Header.Get("DPoP")
	httpURL := tokenEndpointURL(r)
	switch grantType {
	case models.GrantTypeAuthorizationCode:
		req := internalas.TokenRequest{
			GrantType:           grantType,
			ClientID:            clientID,
			ClientSecret:        clientSecret,
			Code:                r.PostFormValue("code"),
			CodeVerifier:        r.PostFormValue("code_verifier"),
			RedirectURI:         r.PostFormValue("redirect_uri"),
			DPoPProof:           dpopHeader,
			HTTPMethod:          r.Method,
			HTTPURL:             httpURL,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     clientAssertion,
		}
		resp, err := h.svc.ExchangeAuthorizationCode(r.Context(), req)
		if err != nil {
			h.writeTokenErrorDPoP(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeRefreshToken:
		req := internalas.TokenRequest{
			GrantType:           grantType,
			ClientID:            clientID,
			ClientSecret:        clientSecret,
			RefreshToken:        r.PostFormValue("refresh_token"),
			Resource:            r.PostFormValue("resource"),
			Scope:               scopeSplit(r.PostFormValue("scope")),
			DPoPProof:           dpopHeader,
			HTTPMethod:          r.Method,
			HTTPURL:             httpURL,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     clientAssertion,
		}
		resp, err := h.svc.RefreshAccessToken(r.Context(), req)
		if err != nil {
			h.writeTokenErrorDPoP(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeClientCredentials:
		req := internalas.TokenRequest{
			GrantType:           grantType,
			ClientID:            clientID,
			ClientSecret:        clientSecret,
			Resource:            r.PostFormValue("resource"),
			Scope:               scopeSplit(r.PostFormValue("scope")),
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     clientAssertion,
		}
		resp, err := h.svc.ClientCredentialsToken(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeTokenExchange:
		req := internalas.TokenExchangeRequest{
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
		resp, err := h.svc.ExchangeToken(r.Context(), req)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeJWTBearer:
		assertion := r.PostFormValue("assertion")
		req := internalas.TokenRequest{
			GrantType:           grantType,
			ClientID:            clientID,
			ClientSecret:        clientSecret,
			Resource:            r.PostFormValue("resource"),
			Scope:               scopeSplit(r.PostFormValue("scope")),
			Assertion:           assertion,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     clientAssertion,
		}
		resp, err := h.svc.JWTBearerGrant(r.Context(), req, assertion)
		if err != nil {
			writeTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	default:
		writeOAuthError(w, http.StatusBadRequest, oauthErrUnsupportedGrantType, "grant_type not supported")
	}
}

// jwtPeekIss extracts the iss claim from a compact JWT without verifying
// the signature. Used to extract client_id from client_assertion when the
// caller does not include it as a separate form field (RFC 7523 permits
// this; the AS must extract it from the assertion).
func jwtPeekIss(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return ""
	}
	return c.Iss
}

func writeTokenJSON(w http.ResponseWriter, resp internalas.TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, err error) {
	code := mapOAuthErrorCode(err)
	status := http.StatusBadRequest
	if code == oauthErrInvalidClient {
		status = http.StatusUnauthorized
	}
	writeOAuthError(w, status, code, err.Error())
}

// ---------- revoke ----------

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	token := r.PostFormValue("token")
	hint := r.PostFormValue("token_type_hint")
	if err := h.svc.RevokeToken(r.Context(), token, hint, clientID, clientSecret); err != nil {
		if errors.Is(err, models.ErrOAuthInvalidClient) {
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------- introspect ----------

func (h *Handler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	token := r.PostFormValue("token")
	aud := r.PostFormValue("resource")
	_, body, err := h.svc.IntrospectToken(r.Context(), token, clientID, clientSecret, aud)
	if err != nil {
		if errors.Is(err, models.ErrOAuthInvalidClient) {
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, err.Error())
		return
	}
	maxAge := int(h.svc.Cfg.IntrospectionCacheTTL.Seconds())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(maxAge))
	_, _ = w.Write(body)
}

// ---------- register ----------

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req internalas.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON")
		return
	}
	anonymous := true
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "Authorization scheme must be Bearer")
			return
		}
		rawToken := strings.TrimSpace(authz[len("bearer "):])
		if !h.dcrBearerValid(rawToken) {
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "invalid initial access token")
			return
		}
		anonymous = false
	}
	resp, err := h.svc.RegisterClient(r.Context(), req, anonymous)
	if err != nil {
		if errors.Is(err, models.ErrOAuthRegistrationDenied) {
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "anonymous registration not permitted")
			return
		}
		var te *models.TheAuthError
		if errors.As(err, &te) {
			writeOAuthError(w, http.StatusBadRequest, te.Code, te.Message)
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------- helpers ----------

// parseClientCredentials extracts client_id / client_secret from the
// request. HTTP Basic auth takes precedence per RFC 6749 section 2.3.1;
// absent that, fall back to client_id / client_secret in the form body.
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

// dcrBearerValid reports whether the supplied raw token (no "Bearer "
// prefix) matches any operator-configured RegistrationTokens entry.
// The comparison runs against pre-computed sha256 digests under
// crypto/subtle.ConstantTimeCompare; the loop walks every configured
// digest so an attacker cannot probe individual tokens via timing.
// Returns false when the input is empty or when no tokens are
// configured (security audit H1, 2026-06-20).
func (h *Handler) dcrBearerValid(rawToken string) bool {
	if rawToken == "" || len(h.bearerHashes) == 0 {
		return false
	}
	candidate := sha256.Sum256([]byte(rawToken))
	matched := 0
	for i := range h.bearerHashes {
		if subtle.ConstantTimeCompare(candidate[:], h.bearerHashes[i][:]) == 1 {
			matched = 1
		}
	}
	return matched == 1
}

// mapOAuthErrorCode maps internal sentinels to wire error codes.
func mapOAuthErrorCode(err error) string {
	switch {
	case errors.Is(err, models.ErrOAuthInvalidRequest),
		errors.Is(err, models.ErrChainDepthExceeded),
		errors.Is(err, models.ErrSubjectTokenInvalid),
		errors.Is(err, models.ErrActorTokenInvalid):
		return oauthErrInvalidRequest
	case errors.Is(err, models.ErrOAuthInvalidClient):
		return oauthErrInvalidClient
	case errors.Is(err, models.ErrOAuthInvalidGrant),
		errors.Is(err, models.ErrOAuthRedirectURIMismatch),
		errors.Is(err, models.ErrOAuthPKCEMismatch):
		return oauthErrInvalidGrant
	case errors.Is(err, models.ErrOAuthInvalidScope):
		return oauthErrInvalidScope
	case errors.Is(err, models.ErrOAuthUnsupportedGrantType):
		return oauthErrUnsupportedGrantType
	case errors.Is(err, models.ErrOAuthUnsupportedResponseType):
		return oauthErrUnsupportedResponseType
	case errors.Is(err, models.ErrOAuthInvalidResource):
		return oauthErrInvalidTarget
	case errors.Is(err, models.ErrAgentInactive),
		errors.Is(err, models.ErrDelegationNotFound),
		errors.Is(err, models.ErrDelegationRevoked):
		return oauthErrAccessDenied
	}
	return oauthErrServerError
}

// OAuth wire error codes. Package-private mirrors of the exported
// OAuthErr* constants in root errors_v20.go; kept here so the
// extracted handler does not import root just to read string
// constants.
const (
	oauthErrInvalidRequest          = "invalid_request"
	oauthErrInvalidClient           = "invalid_client"
	oauthErrInvalidGrant            = "invalid_grant"
	oauthErrInvalidScope            = "invalid_scope"
	oauthErrUnsupportedGrantType    = "unsupported_grant_type"
	oauthErrUnsupportedResponseType = "unsupported_response_type"
	oauthErrAccessDenied            = "access_denied"
	oauthErrServerError             = "server_error"
	oauthErrInvalidTarget           = "invalid_target"
	// RFC 9449 wire codes returned from the token endpoint when a DPoP
	// proof is missing, malformed, or rejected.
	oauthErrInvalidDPoPProof = "invalid_dpop_proof"
	oauthErrUseDPoPNonce     = "use_dpop_nonce"
)

// tokenEndpointURL returns the canonical https://host/oauth/token URL
// the DPoP verifier expects. We rebuild it from the request rather than
// trusting r.URL because chi normalizes paths but does not populate
// scheme/host. When the deployment uses a reverse proxy that terminates
// TLS the X-Forwarded-Proto + Host headers are honored.
func tokenEndpointURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host + r.URL.Path
}

// writeTokenErrorDPoP extends writeTokenError with the RFC 9449
// invalid_dpop_proof / use_dpop_nonce wire mapping. When the AS demands
// a nonce, a fresh DPoP-Nonce header accompanies the 400 response so the
// client can immediately retry.
func (h *Handler) writeTokenErrorDPoP(w http.ResponseWriter, err error) {
	if errors.Is(err, internalas.ErrDPoPNonceRequired) {
		nonce := h.svc.IssueDPoPNonce()
		if nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
		}
		writeOAuthError(w, http.StatusBadRequest, oauthErrUseDPoPNonce, "DPoP proof nonce required")
		return
	}
	if errors.Is(err, internalas.ErrDPoPRequired) {
		nonce := h.svc.IssueDPoPNonce()
		if nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
		}
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidDPoPProof, "DPoP proof required for this client")
		return
	}
	if errors.Is(err, internalas.ErrDPoPInvalid) {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidDPoPProof, err.Error())
		return
	}
	writeTokenError(w, err)
}

// scopeSplit parses a space-separated scope string into a deduped
// slice preserving order of first occurrence. Mirrors the legacy root
// scope_helpers.go::scopeSplit, kept package-private here because
// handlers_oauth_server.go was the only consumer.
func scopeSplit(s string) []string {
	parts := strings.Fields(s)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

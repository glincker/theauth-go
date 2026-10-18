// Package handlers serves the OAuth 2.1 and MCP authorization server HTTP endpoints: metadata,
// JWKS, authorize, token, revoke, introspect and register. Routes are listed in Mount.
package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/go-chi/chi/v5"
)

// Handler owns the AS HTTP surface.
type Handler struct {
	svc          *internalas.Service
	userFromCtx  func(r *http.Request) (*models.User, bool)
	bearerHashes [][32]byte
	clientIP     func(r *http.Request) string
	// authContext reports how the request's session authenticated. Nil leaves tokens without
	// auth_time, acr and amr.
	authContext  func(r *http.Request) (internalas.AuthContext, bool)
	sessionEnder func(w http.ResponseWriter, r *http.Request)
	// cors holds the opt-in CORS policy, built in Mount from the AS config. Inert for the zero config.
	cors *internalas.CORSPolicy
}

// New constructs a Handler. userFromCtx reads the user the Authn middleware attached. bearerHashes
// are the digests of the operator DCR registration tokens; empty means no bearer-gated registration
// is permitted.
func New(svc *internalas.Service, userFromCtx func(r *http.Request) (*models.User, bool), bearerHashes [][32]byte) *Handler {
	return &Handler{svc: svc, userFromCtx: userFromCtx, bearerHashes: bearerHashes}
}

// corsPreflight registers OPTIONS on each path when CORS is enabled for g. It sits outside the
// authn and rate limit middleware so a preflight never needs credentials.
func (h *Handler) corsPreflight(r chi.Router, g internalas.CORSGroup, paths ...string) {
	if !h.cors.Enabled(g) {
		return
	}
	for _, p := range paths {
		r.Options(p, h.cors.Preflight(g))
	}
}

// Mount registers the AS routes on r. authn guards /oauth/authorize, and rateLimit (may be nil)
// caps /oauth/register.
func (h *Handler) Mount(r chi.Router, authn func(http.Handler) http.Handler, registerLimit func(http.Handler) http.Handler) {
	h.cors = internalas.NewCORSPolicy(h.svc.Cfg.CORS)
	disc := h.cors.Middleware(internalas.CORSDiscovery)
	h.corsPreflight(r, internalas.CORSDiscovery,
		"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/*",
		"/.well-known/openid-configuration", "/.well-known/openid-configuration/*",
		"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/*")
	h.corsPreflight(r, internalas.CORSJWKS, "/oauth/jwks")
	h.corsPreflight(r, internalas.CORSToken, "/oauth/token")
	h.corsPreflight(r, internalas.CORSRevoke, "/oauth/revoke")
	h.corsPreflight(r, internalas.CORSIntrospect, "/oauth/introspect")
	h.corsPreflight(r, internalas.CORSRegister, "/oauth/register")
	r.With(disc).Get("/.well-known/oauth-authorization-server", h.handleASMetadata)
	// RFC 8414 section 3.1: with an issuer path, the well-known segment goes between host and path.
	// The OIDC discovery name is served too, since MCP clients probe both.
	r.With(disc).Get("/.well-known/oauth-authorization-server/*", h.handleASMetadataPath)
	r.With(disc).Get("/.well-known/openid-configuration", h.handleASMetadata)
	r.With(disc).Get("/.well-known/openid-configuration/*", h.handleASMetadataPath)
	r.With(disc).Get("/.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	r.With(disc).Get("/.well-known/oauth-protected-resource/*", h.handleProtectedResourceMetadata)
	r.With(h.cors.Middleware(internalas.CORSJWKS)).Get("/oauth/jwks", h.handleJWKS)
	r.With(authn).Get("/oauth/authorize", h.handleAuthorize)
	r.With(h.cors.Middleware(internalas.CORSToken), h.limited).Post("/oauth/token", h.handleToken)
	r.With(h.cors.Middleware(internalas.CORSRevoke), h.limited).Post("/oauth/revoke", h.handleRevoke)
	r.With(h.cors.Middleware(internalas.CORSIntrospect), h.limited).Post("/oauth/introspect", h.handleIntrospect)
	regCORS := h.cors.Middleware(internalas.CORSRegister)
	if registerLimit != nil {
		r.With(regCORS, registerLimit).Post("/oauth/register", h.handleRegister)
	} else {
		r.With(regCORS).Post("/oauth/register", h.handleRegister)
	}
	// PAR (RFC 9126) is registered only when enabled and supported, so unknown routes get a 405 rather
	// than a handler error.
	if h.svc.IsPAREnabled() {
		r.With(h.limited).Post("/oauth/par", h.handlePAR)
	}
	if h.svc.IsCIBAEnabled() {
		r.With(h.limited).Post("/oauth/bc-authorize", h.handleBCAuthorize)
	}
	if h.svc.IsDeviceEnabled() {
		h.mountDevice(r, authn)
	}
	if h.svc.OIDCEnabled() {
		h.mountOIDC(r, authn)
	}
	if h.svc.DeviceTokensEnabled() {
		h.mountDeviceIdentity(r)
	}
}

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

// handleASMetadataPath serves the RFC 8414 path-inserted form. A different issuer path gets a 404.
func (h *Handler) handleASMetadataPath(w http.ResponseWriter, r *http.Request) {
	want := "/" + strings.Trim(chi.URLParam(r, "*"), "/")
	got := ""
	if u, err := url.Parse(h.svc.Cfg.Issuer); err == nil {
		got = "/" + strings.Trim(u.Path, "/")
	}
	if want != got {
		http.NotFound(w, r)
		return
	}
	h.handleASMetadata(w, r)
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
			} else if id, ok := h.resourceByPath(resourceID); ok {
				// RFC 9728 section 3.1: the suffix is the resource path, and the resource may live on another
				// origin than the issuer.
				ident = id
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

// resourceByPath finds the configured resource whose identifier path equals the well-known suffix.
func (h *Handler) resourceByPath(suffix string) (string, bool) {
	want := "/" + strings.Trim(suffix, "/")
	for _, res := range h.svc.Cfg.Resources {
		u, err := url.Parse(res.Identifier)
		if err != nil {
			continue
		}
		if "/"+strings.Trim(u.Path, "/") == want {
			return res.Identifier, true
		}
	}
	return "", false
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

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	requestURI := q.Get("request_uri")
	requestObject := q.Get("request")

	if requestURI != "" && requestObject != "" {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "request and request_uri are mutually exclusive")
		return
	}

	var req internalas.AuthorizeRequest

	switch {
	case requestURI != "":
		// PAR path: consume the pushed request. RFC 9126 section 3 forbids inline params (other than
		// client_id) alongside request_uri.
		if hasInlineAuthorizeParams(q, clientID) {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "inline params must not accompany request_uri")
			return
		}
		var err error
		req, err = h.svc.ConsumePushedRequest(r.Context(), requestURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "invalid or expired request_uri")
			return
		}
		if clientID != "" && req.ClientID != clientID {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "client_id mismatch with request_uri")
			return
		}

	case requestObject != "":
		// JAR path: parse and verify the request JWT. RFC 9101 section 5: outer params (except client_id)
		// are ignored.
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
		if req.ClientID == "" {
			req.ClientID = clientID
		}

	default:
		if h.svc.Cfg.PAR != nil && h.svc.Cfg.PAR.RequirePAR {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "pushed_authorization_request_required")
			return
		}
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
			ACRValues:           strings.Fields(q.Get("acr_values")),
			Prompt:              q.Get("prompt"),

			AuthorizationDetails: q.Get("authorization_details"),
		}
		maxAge, merr := internalas.ParseMaxAge(q.Get("max_age"))
		if merr != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "max_age must be a non-negative integer")
			return
		}
		req.MaxAge = maxAge
	}

	user, _ := h.userFromCtx(r)
	ctx := r.Context()
	if user != nil && h.authContext != nil {
		if ac, ok := h.authContext(r); ok {
			ctx = internalas.WithAuthContext(ctx, ac)
		}
	}
	res, err := h.svc.StartAuthorize(ctx, req, user)
	if err != nil {
		if internalas.IsLoginRequired(err) || internalas.IsReauthRequired(err) {
			if req.Prompt == "none" {
				// OIDC Core 3.1.2.6: prompt=none never shows a login page.
				h.writeAuthorizeError(w, r, req, errLoginRequired)
				return
			}
			http.Redirect(w, r, h.loginRedirect(r, req, internalas.IsReauthRequired(err)), http.StatusFound)
			return
		}
		h.writeAuthorizeError(w, r, req, err)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

// hasInlineAuthorizeParams reports whether the query carries an authorization parameter other than
// client_id and request_uri.
func hasInlineAuthorizeParams(q url.Values, clientID string) bool {
	check := []string{
		"response_type", "redirect_uri", "scope", "state",
		"code_challenge", "code_challenge_method", "resource", "nonce",
		"authorization_details", "max_age", "acr_values", "prompt",
	}
	for _, k := range check {
		if q.Get(k) != "" {
			return true
		}
	}
	return false
}

func (h *Handler) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, _ := parseClientCredentials(r)

	// JAR inside PAR: a "request" parameter is unpacked from its JWT (RFC 9101 inside RFC 9126).
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
			ACRValues:           strings.Fields(r.PostFormValue("acr_values")),
			Prompt:              r.PostFormValue("prompt"),

			AuthorizationDetails: r.PostFormValue("authorization_details"),
		}
		maxAge, merr := internalas.ParseMaxAge(r.PostFormValue("max_age"))
		if merr != nil {
			writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "max_age must be a non-negative integer")
			return
		}
		req.MaxAge = maxAge
	}

	resp, err := h.svc.PushAuthorize(r.Context(), req)
	if err != nil {
		if isBusy(err) {
			writeBusy(w)
			return
		}
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

func (h *Handler) writeAuthorizeError(w http.ResponseWriter, r *http.Request, req internalas.AuthorizeRequest, err error) {
	code := mapOAuthErrorCode(err)
	if req.RedirectURI != "" && h.svc.RedirectURIRegisteredFor(r.Context(), req.ClientID, req.RedirectURI) && code != oauthErrInvalidRequest && code != oauthErrInvalidTarget {
		u, perr := url.Parse(req.RedirectURI)
		if perr == nil {
			qq := u.Query()
			qq.Set("error", code)
			qq.Set("iss", h.svc.Cfg.Issuer)
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

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	grantType := r.PostFormValue("grant_type")
	clientAssertionType := r.PostFormValue("client_assertion_type")
	clientAssertion := r.PostFormValue("client_assertion")
	// Without client_id, take it from the assertion iss claim (RFC 7523 requires iss = client_id).
	if clientID == "" && clientAssertion != "" {
		clientID = jwtPeekIss(clientAssertion)
	}
	// The DPoP proof arrives in the DPoP header (RFC 9449 section 4). The verifier strips the query from htu.
	dpopHeader := r.Header.Get("DPoP")
	// The DPoP htu comes from the configured issuer, never from request headers: X-Forwarded-* are
	// client controlled unless a proxy scrubs them, so trusting them would let a proof for another
	// origin pass.
	httpURL := h.svc.TokenEndpointURL()
	// authorization_details is honoured only on the code and refresh grants. Ignoring it elsewhere
	// would issue a token that differs from what the caller asked for, so it is refused.
	if r.PostFormValue("authorization_details") != "" &&
		grantType != models.GrantTypeAuthorizationCode && grantType != models.GrantTypeRefreshToken {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidAuthorizationDetails, "authorization_details is not supported for this grant")
		return
	}
	switch grantType {
	case models.GrantTypeAuthorizationCode:
		req := internalas.TokenRequest{
			GrantType:    grantType,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Code:         r.PostFormValue("code"),
			CodeVerifier: r.PostFormValue("code_verifier"),
			RedirectURI:  r.PostFormValue("redirect_uri"),

			AuthorizationDetails: r.PostFormValue("authorization_details"),
			DPoPProof:            dpopHeader,
			HTTPMethod:           r.Method,
			HTTPURL:              httpURL,
			ClientAssertionType:  clientAssertionType,
			ClientAssertion:      clientAssertion,
		}
		resp, err := h.svc.ExchangeAuthorizationCode(r.Context(), req)
		if err != nil {
			h.writeTokenErrorDPoP(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeRefreshToken:
		req := internalas.TokenRequest{
			GrantType:    grantType,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RefreshToken: r.PostFormValue("refresh_token"),
			Resource:     r.PostFormValue("resource"),

			AuthorizationDetails: r.PostFormValue("authorization_details"),
			Scope:                scopeSplit(r.PostFormValue("scope")),
			DPoPProof:            dpopHeader,
			HTTPMethod:           r.Method,
			HTTPURL:              httpURL,
			ClientAssertionType:  clientAssertionType,
			ClientAssertion:      clientAssertion,
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
			DPoPProof:          dpopHeader,
			HTTPMethod:         r.Method,
			HTTPURL:            httpURL,
		}
		resp, err := h.svc.ExchangeToken(r.Context(), req)
		if err != nil {
			h.writeTokenErrorDPoP(w, err)
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
			DPoPProof:           dpopHeader,
			HTTPMethod:          r.Method,
			HTTPURL:             httpURL,
		}
		resp, err := h.svc.JWTBearerGrant(r.Context(), req, assertion)
		if err != nil {
			h.writeTokenErrorDPoP(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeCIBA:
		req := internalas.CIBATokenRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			AuthReqID:    r.PostFormValue("auth_req_id"),
		}
		resp, err := h.svc.PollBackchannelToken(r.Context(), req)
		if err != nil {
			writeCIBATokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	case models.GrantTypeDeviceCode:
		req := internalas.DeviceTokenRequest{
			TokenRequest: internalas.TokenRequest{
				GrantType:           grantType,
				ClientID:            clientID,
				ClientSecret:        clientSecret,
				DPoPProof:           dpopHeader,
				HTTPMethod:          r.Method,
				HTTPURL:             httpURL,
				ClientAssertionType: clientAssertionType,
				ClientAssertion:     clientAssertion,
			},
			DeviceCode: r.PostFormValue("device_code"),
		}
		resp, err := h.svc.PollDeviceToken(r.Context(), req)
		if err != nil {
			h.writeDeviceTokenError(w, err)
			return
		}
		writeTokenJSON(w, resp)
	default:
		writeOAuthError(w, http.StatusBadRequest, oauthErrUnsupportedGrantType, "grant_type not supported")
	}
}

// jwtPeekIss reads the iss claim without verifying the signature. It is used only to find client_id
// for client assertions (RFC 7523).
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
	var limited *internalas.RateLimitedError
	if errors.As(err, &limited) {
		writeRateLimited(w, limited.RetryAfter)
		return
	}
	if isBusy(err) {
		writeBusy(w)
		return
	}
	code := mapOAuthErrorCode(err)
	status := http.StatusBadRequest
	if code == oauthErrInvalidClient {
		status = http.StatusUnauthorized
	}
	writeOAuthError(w, status, code, err.Error())
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, "malformed form")
		return
	}
	clientID, clientSecret := parseClientCredentials(r)
	token := r.PostFormValue("token")
	hint := r.PostFormValue("token_type_hint")
	if err := h.svc.RevokeToken(r.Context(), token, hint, clientID, clientSecret); err != nil {
		if isBusy(err) {
			writeBusy(w)
			return
		}
		if errors.Is(err, models.ErrOAuthInvalidClient) {
			writeOAuthError(w, http.StatusUnauthorized, oauthErrInvalidClient, "client authentication failed")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, oauthErrInvalidRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

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
		if isBusy(err) {
			writeBusy(w)
			return
		}
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

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req internalas.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON")
		return
	}
	anonymous := true
	var spent *models.RegistrationToken
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "Authorization scheme must be Bearer")
			return
		}
		rawToken := strings.TrimSpace(authz[len("bearer "):])
		if !h.dcrBearerValid(rawToken) {
			// Not a static operator token: try stored, scoped, single-use registration tokens.
			t, terr := h.svc.RedeemRegistrationToken(r.Context(), rawToken, req)
			switch {
			case terr == nil:
				spent = t
			case errors.Is(terr, models.ErrRegistrationTokenScope):
				writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "registration request exceeds the scope of the initial access token")
				return
			case errors.Is(terr, models.ErrRegistrationTokenInvalid):
				writeOAuthError(w, http.StatusUnauthorized, "access_denied", "invalid initial access token")
				return
			default:
				writeOAuthError(w, http.StatusInternalServerError, oauthErrServerError, "registration token check failed")
				return
			}
		}
		anonymous = false
	}
	resp, err := h.svc.RegisterClient(r.Context(), req, anonymous)
	if err != nil && spent != nil {
		h.svc.RefundRegistrationToken(r.Context(), spent.ID)
	}
	if err == nil && spent != nil {
		h.svc.RegistrationSucceeded(r.Context(), spent, resp.ClientID)
	}
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

// parseClientCredentials reads client_id and client_secret. HTTP Basic takes precedence (RFC 6749
// section 2.3.1), then the form body.
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

// writeOAuthError writes the standard OAuth error body. Server faults never echo internal error
// text; it goes to the log only.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	if status >= http.StatusInternalServerError || code == oauthErrServerError {
		slog.Error("oauth endpoint server error", "code", code, "detail", description)
		description = "internal server error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: code, ErrorDescription: description})
}

// dcrBearerValid reports whether a raw bearer token matches an operator RegistrationTokens digest.
// The loop visits every digest so timing cannot reveal which token matched (security audit H1).
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

// mapOAuthErrorCode maps internal sentinels to OAuth wire error codes.
func mapOAuthErrorCode(err error) string {
	switch {
	case errors.Is(err, errLoginRequired):
		return oauthErrLoginRequired
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
	case errors.Is(err, models.ErrOAuthInvalidAuthorizationDetails):
		return oauthErrInvalidAuthorizationDetails
	case errors.Is(err, models.ErrOAuthUnsupportedGrantType):
		return oauthErrUnsupportedGrantType
	case errors.Is(err, models.ErrOAuthUnsupportedResponseType):
		return oauthErrUnsupportedResponseType
	case errors.Is(err, models.ErrOAuthInvalidResource):
		return oauthErrInvalidTarget
	case errors.Is(err, models.ErrAgentInactive),
		errors.Is(err, models.ErrAgentPolicyDenied),
		errors.Is(err, models.ErrDelegationNotFound),
		errors.Is(err, models.ErrDelegationRevoked):
		return oauthErrAccessDenied
	}
	return oauthErrServerError
}

// OAuth wire error codes, mirroring the exported OAuthErr* constants at the root.
const (
	oauthErrLoginRequired               = "login_required"
	oauthErrInvalidRequest              = "invalid_request"
	oauthErrInvalidClient               = "invalid_client"
	oauthErrInvalidGrant                = "invalid_grant"
	oauthErrInvalidScope                = "invalid_scope"
	oauthErrUnsupportedGrantType        = "unsupported_grant_type"
	oauthErrUnsupportedResponseType     = "unsupported_response_type"
	oauthErrAccessDenied                = "access_denied"
	oauthErrServerError                 = "server_error"
	oauthErrInvalidTarget               = "invalid_target"
	oauthErrInvalidAuthorizationDetails = "invalid_authorization_details"
	// RFC 9449 wire codes for a missing, malformed or rejected DPoP proof at the token endpoint.
	oauthErrInvalidDPoPProof = "invalid_dpop_proof"
	oauthErrUseDPoPNonce     = "use_dpop_nonce"
)

// writeTokenErrorDPoP extends writeTokenError with the RFC 9449 mappings. A demanded nonce gets a
// fresh DPoP-Nonce header so the client can retry at once.
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

// scopeSplit parses a space-separated scope string into a deduped slice, keeping first occurrences in order.
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

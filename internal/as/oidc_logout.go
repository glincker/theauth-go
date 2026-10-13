package as

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/safehttp"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// oidc_logout.go: RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

// backchannelLogoutEvent is the key of the events claim in a logout token.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout" // NOSONAR go:S5332 event identifier fixed by the spec, not a URL fetched

// logoutTokenTTL is how long a delivered logout token stays valid.
const logoutTokenTTL = 2 * time.Minute

// ErrEndSessionInvalid wraps every end_session request the server refuses.
var ErrEndSessionInvalid = errors.New("end_session: invalid request")

// EndSessionRequest is the parsed end_session request plus the session the
// browser presented, when any.
type EndSessionRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string

	// SessionID and UserID identify the session behind the request's
	// cookie. Empty when the browser has none.
	SessionID string
	UserID    *models.ULID
}

// EndSessionResult tells the handler where to send the user agent. An empty
// RedirectURL means render the signed-out page.
type EndSessionResult struct {
	RedirectURL string
}

// EndSession validates an RP-initiated logout request and notifies the
// session's clients through back-channel logout. The caller ends the session
// itself afterwards.
func (s *Service) EndSession(ctx context.Context, req EndSessionRequest) (EndSessionResult, error) {
	if !s.OIDCEnabled() {
		return EndSessionResult{}, errOIDCDisabled
	}
	clientID := req.ClientID
	var hintSub string
	if req.IDTokenHint != "" {
		c, err := jwt.VerifyWith(req.IDTokenHint, s.VerificationKey, "JWT", "", time.Now(),
			jwt.VerifyOptions{IgnoreExpiry: true})
		if err != nil || c.Iss != s.Cfg.Issuer || c.Aud == "" {
			return EndSessionResult{}, fmt.Errorf("%w: id_token_hint is not an ID token from this server", ErrEndSessionInvalid)
		}
		if clientID != "" && clientID != c.Aud {
			return EndSessionResult{}, fmt.Errorf("%w: client_id does not match id_token_hint", ErrEndSessionInvalid)
		}
		clientID, hintSub = c.Aud, c.Sub
	}
	var client *models.OAuthClient
	if clientID != "" {
		c, err := s.ResolveClient(ctx, clientID)
		if err != nil {
			return EndSessionResult{}, fmt.Errorf("%w: unknown client", ErrEndSessionInvalid)
		}
		client = c
	}
	if hintSub != "" && req.UserID != nil && hintSub != s.subjectFor(client, req.UserID.String()) {
		return EndSessionResult{}, fmt.Errorf("%w: id_token_hint does not belong to the signed-in user", ErrEndSessionInvalid)
	}
	redirect := ""
	if req.PostLogoutRedirectURI != "" {
		reg := ""
		if client != nil {
			// Use the registered string, never the request's copy.
			for _, u := range client.PostLogoutRedirectURIs {
				if u == req.PostLogoutRedirectURI {
					reg = u
					break
				}
			}
		}
		if reg == "" {
			return EndSessionResult{}, fmt.Errorf("%w: post_logout_redirect_uri is not registered", ErrEndSessionInvalid)
		}
		redirect = reg
		if req.State != "" {
			if strings.Contains(reg, "?") {
				redirect = reg + "&state=" + url.QueryEscape(req.State)
			} else {
				redirect = reg + "?state=" + url.QueryEscape(req.State)
			}
		}
	}
	if req.SessionID != "" && req.UserID != nil {
		s.NotifyLogout(ctx, *req.UserID, req.SessionID)
	}
	return EndSessionResult{RedirectURL: redirect}, nil
}

// NotifyLogout sends a back-channel logout token to every client that took
// part in sessionID and forgets the session. Deliveries run in the
// background; failures are logged and never block the caller.
func (s *Service) NotifyLogout(ctx context.Context, userID models.ULID, sessionID string) {
	if !s.OIDCEnabled() || sessionID == "" {
		return
	}
	clients := s.sessionClients(ctx, sessionID)
	if s.oidcCache != nil {
		_ = s.oidcCache.Delete(ctx, oidcSessKeyPrefix+sessionID)
	}
	bg := context.WithoutCancel(ctx)
	for _, clientID := range clients {
		client, err := s.ResolveClient(bg, clientID)
		if err != nil || client.BackchannelLogoutURI == "" {
			continue
		}
		s.logoutWG.Add(1)
		go func() {
			defer s.logoutWG.Done()
			if err := s.deliverLogoutToken(bg, client, userID, sessionID); err != nil {
				slog.Warn("theauth: back-channel logout failed", "client_id", client.ClientID, "err", err.Error())
			}
		}()
	}
}

// WaitLogoutDeliveries blocks until in-flight back-channel deliveries end.
func (s *Service) WaitLogoutDeliveries() { s.logoutWG.Wait() }

func (s *Service) logoutHTTPClient() *http.Client {
	if s.Cfg.OIDC.HTTPClient != nil {
		return s.Cfg.OIDC.HTTPClient
	}
	return safehttp.NewClient(s.Cfg.OIDC.BackchannelLogoutTimeout, s.Cfg.OIDC.AllowPrivateNetworks)
}

func (s *Service) deliverLogoutToken(ctx context.Context, client *models.OAuthClient, userID models.ULID, sessionID string) error {
	token, err := s.signLogoutToken(ctx, client, userID, sessionID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.Cfg.OIDC.BackchannelLogoutTimeout)
	defer cancel()
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BackchannelLogoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := s.logoutHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("endpoint answered %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) signLogoutToken(ctx context.Context, client *models.OAuthClient, userID models.ULID, sessionID string) (string, error) {
	_, alg := s.accessTokenPolicy(ctx, client.ClientID)
	key, signer, err := s.SigningKeyFor(ctx, alg)
	if err != nil {
		return "", err
	}
	now := s.Cfg.Clock.Now().UTC()
	claims := map[string]any{
		"iss":    s.Cfg.Issuer,
		"aud":    client.ClientID,
		"iat":    now.Unix(),
		"exp":    now.Add(logoutTokenTTL).Unix(),
		"jti":    ulid.New().String(),
		"sub":    s.subjectFor(client, userID.String()),
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
	claims["sid"] = s.sidFor(sessionID, client.ClientID)
	return jwt.SignPayloadWith(claims, jwt.TypeLogoutToken, key.KID, alg, signer)
}

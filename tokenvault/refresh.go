package tokenvault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidGrant is returned by a Refresher when the provider rejects the
// refresh token for good (revoked or expired). The vault then marks the
// credential as needing the user to reconnect.
var ErrInvalidGrant = errors.New("tokenvault: provider rejected the refresh token")

// TokenResponse is the result of a refresh. Empty fields mean "unchanged".
type TokenResponse struct {
	AccessToken string
	// RefreshToken is set when the provider rotated the refresh token.
	RefreshToken string
	// ExpiresIn is zero when the provider gave no lifetime.
	ExpiresIn time.Duration
	Scopes    []string
}

// Refresher exchanges a refresh token for a new access token at one provider.
type Refresher interface {
	Refresh(ctx context.Context, refreshToken string) (TokenResponse, error)
}

// OAuthRefresher implements the RFC 6749 section 6 refresh grant.
type OAuthRefresher struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	// AuthStyle selects how client credentials are sent. The zero value is
	// AuthBasic, the original behavior.
	AuthStyle AuthStyle
	// AllowInsecureHTTP permits a non https TokenURL. Tests and local demos only.
	AllowInsecureHTTP bool
}

const maxTokenBody = 1 << 20

// Refresh implements Refresher. Error values never contain a token or the
// response body.
func (o OAuthRefresher) Refresh(ctx context.Context, refreshToken string) (TokenResponse, error) {
	u, err := url.Parse(o.TokenURL)
	if err != nil || (u.Scheme != "https" && (!o.AllowInsecureHTTP || u.Scheme != "http")) {
		return TokenResponse{}, errors.New("tokenvault: token URL must be https")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if o.AuthStyle == AuthPost {
		form.Set("client_id", o.ClientID)
		form.Set("client_secret", o.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, errors.New("tokenvault: build refresh request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if o.AuthStyle != AuthPost {
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(o.ClientSecret))
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, errors.New("tokenvault: refresh request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody))
	if err != nil {
		return TokenResponse{}, errors.New("tokenvault: read refresh response")
	}
	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	if resp.StatusCode != http.StatusOK {
		if parsed.Error == "invalid_grant" {
			return TokenResponse{}, ErrInvalidGrant
		}
		return TokenResponse{}, fmt.Errorf("tokenvault: provider returned status %d", resp.StatusCode)
	}
	if parsed.AccessToken == "" {
		return TokenResponse{}, errors.New("tokenvault: provider returned no access token")
	}
	return TokenResponse{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresIn:    time.Duration(parsed.ExpiresIn) * time.Second,
		Scopes:       strings.Fields(parsed.Scope),
	}, nil
}

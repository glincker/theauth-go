// Package refresh implements the RFC 6749 section 6 refresh_token grant
// shared by the in-tree providers.
package refresh

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

	"github.com/glincker/theauth-go/v2"
)

// Request describes one refresh call.
type Request struct {
	// Provider names the provider in error messages.
	Provider     string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RefreshToken string
	// BasicAuth sends client credentials in an Authorization header instead
	// of the form body.
	BasicAuth bool
	// Scope optionally narrows the refreshed token.
	Scope  string
	Client *http.Client
}

// revokedCodes are the token endpoint error codes that mean the refresh token
// is no longer usable. GitHub answers bad_refresh_token with status 200.
var revokedCodes = map[string]bool{
	"invalid_grant":     true,
	"bad_refresh_token": true,
}

// Do performs the refresh and returns the new token. A refresh token the
// provider rejects yields an error wrapping theauth.ErrProviderGrantRevoked.
// RefreshToken in the result is empty when the provider did not rotate it.
func Do(ctx context.Context, r Request) (*theauth.ProviderToken, error) {
	if r.RefreshToken == "" {
		return nil, fmt.Errorf("%s token refresh: %w", r.Provider, theauth.ErrProviderRefreshUnsupported)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", r.RefreshToken)
	if r.Scope != "" {
		form.Set("scope", r.Scope)
	}
	if !r.BasicAuth {
		form.Set("client_id", r.ClientID)
		if r.ClientSecret != "" {
			form.Set("client_secret", r.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.BasicAuth {
		req.SetBasicAuth(url.QueryEscape(r.ClientID), url.QueryEscape(r.ClientSecret))
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s token refresh: %w", r.Provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("%s token refresh: %w", r.Provider, err)
	}

	var raw struct {
		AccessToken      string    `json:"access_token"`
		RefreshToken     string    `json:"refresh_token"`
		ExpiresIn        int64     `json:"expires_in"`
		Scope            flexScope `json:"scope"`
		TokenType        string    `json:"token_type"`
		IDToken          string    `json:"id_token"`
		Error            string    `json:"error"`
		ErrorDescription string    `json:"error_description"`
	}
	parseErr := json.Unmarshal(body, &raw)
	if raw.Error != "" || resp.StatusCode/100 != 2 {
		if revokedCodes[raw.Error] {
			return nil, fmt.Errorf("%s token refresh: %w: %s %s", r.Provider, theauth.ErrProviderGrantRevoked, raw.Error, raw.ErrorDescription)
		}
		if raw.Error != "" {
			return nil, fmt.Errorf("%s token refresh: status=%d %s: %s", r.Provider, resp.StatusCode, raw.Error, raw.ErrorDescription)
		}
		return nil, fmt.Errorf("%s token refresh: status=%d", r.Provider, resp.StatusCode)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("%s token refresh: parse: %w", r.Provider, parseErr)
	}
	if raw.AccessToken == "" {
		return nil, errors.New(r.Provider + " token refresh: missing access_token in response")
	}
	tok := &theauth.ProviderToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		Scope:        string(raw.Scope),
		TokenType:    raw.TokenType,
		IDToken:      raw.IDToken,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// flexScope reads a token response "scope" that is a string or an array of
// strings (Linear answers an array for older apps). Arrays are joined with a
// space. Any other JSON type reads as empty instead of failing the refresh.
type flexScope string

func (f *flexScope) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexScope(s)
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*f = flexScope(strings.Join(list, " "))
		return nil
	}
	*f = ""
	return nil
}

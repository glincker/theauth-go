package clientauth

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

// ErrReloginRequired means the stored token is expired or no longer accepted; run the login flow again.
var ErrReloginRequired = errors.New("clientauth: session expired, log in again")

// Client sends authenticated requests to one theauth-go server.
type Client struct {
	ServerURL string
	// AuthPath is the route prefix on the server. Default DefaultAuthPath.
	AuthPath string
	Store    TokenStore
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Now defaults to time.Now.
	Now func() time.Time
	// SelfPath is the bearer-authenticated route for Whoami and Logout,
	// relative to the auth path. Default "/tokens/current".
	SelfPath string
}

// NewClient returns a Client for serverURL backed by store.
func NewClient(serverURL string, store TokenStore) (*Client, error) {
	norm, err := NormalizeServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	return &Client{ServerURL: norm, Store: store}, nil
}

func (c *Client) hc() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) selfURL() string {
	ap, sp := c.AuthPath, c.SelfPath
	if ap == "" {
		ap = DefaultAuthPath
	}
	if sp == "" {
		sp = "/tokens/current"
	}
	return c.ServerURL + "/" + strings.Trim(ap, "/") + "/" + strings.Trim(sp, "/")
}

// NewRequest builds a request for a path on the server.
func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.ServerURL+"/"+strings.TrimLeft(path, "/"), body)
	if err != nil {
		return nil, fmt.Errorf("clientauth: build request: %w", err)
	}
	return req, nil
}

// Do attaches the stored bearer token and sends req. It returns
// ErrNotLoggedIn without a credential and ErrReloginRequired when the token
// is expired locally or the server answers 401. Requests to any other origin
// are refused so the token cannot leak.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if !sameOrigin(c.ServerURL, req) {
		return nil, fmt.Errorf("clientauth: refusing to send credentials to %s", req.URL.Host)
	}
	cred, err := c.Store.Load(req.Context(), c.ServerURL)
	if err != nil {
		return nil, err
	}
	if cred.Expired(c.now()) {
		return nil, ErrReloginRequired
	}
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	resp, err := c.hc().Do(out)
	if err != nil {
		return nil, fmt.Errorf("clientauth: request failed: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		_ = resp.Body.Close()
		return nil, ErrReloginRequired
	}
	return resp, nil
}

func sameOrigin(server string, req *http.Request) bool {
	base, err := url.Parse(server)
	if err != nil {
		return false
	}
	return strings.EqualFold(base.Scheme, req.URL.Scheme) && strings.EqualFold(base.Host, req.URL.Host)
}

// Identity describes the stored token as the server sees it.
type Identity struct {
	ID         string     `json:"id"`
	OwnerID    string     `json:"ownerId"`
	OwnerKind  string     `json:"ownerKind"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	AgentName  string     `json:"agentName"`
	Abilities  []string   `json:"abilities"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

// Whoami asks the server which token and owner the stored credential maps to.
func (c *Client) Whoami(ctx context.Context) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.selfURL(), nil)
	if err != nil {
		return Identity{}, fmt.Errorf("clientauth: build whoami request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	if err != nil {
		return Identity{}, fmt.Errorf("clientauth: read whoami response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Identity{}, parseServerError(resp.StatusCode, body)
	}
	var id Identity
	if err := json.Unmarshal(body, &id); err != nil {
		return Identity{}, fmt.Errorf("clientauth: decode whoami response: %w", err)
	}
	return id, nil
}

// Logout revokes the token on the server, then deletes it locally. The local
// copy is removed even when revocation fails, and that failure is returned.
func (c *Client) Logout(ctx context.Context) error {
	if _, err := c.Store.Load(ctx, c.ServerURL); err != nil {
		return err
	}
	revokeErr := c.revoke(ctx)
	if err := c.Store.Delete(ctx, c.ServerURL); err != nil {
		return errors.Join(revokeErr, fmt.Errorf("clientauth: delete local credential: %w", err))
	}
	if errors.Is(revokeErr, ErrReloginRequired) {
		return nil
	}
	return revokeErr
}

func (c *Client) revoke(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.selfURL(), nil)
	if err != nil {
		return fmt.Errorf("clientauth: build revoke request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		if errors.Is(err, ErrReloginRequired) {
			return err
		}
		return fmt.Errorf("clientauth: revoke token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	return fmt.Errorf("clientauth: revoke token: %w", parseServerError(resp.StatusCode, body))
}

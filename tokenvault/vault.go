package tokenvault

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// Errors returned by Vault. Callers acting for an agent should map them all to
// one generic refusal; the distinct values exist for logs and tests.
var (
	ErrScopesRequired   = errors.New("tokenvault: at least one scope is required")
	ErrNotDelegated     = errors.New("tokenvault: user has not delegated this provider and scope to the agent")
	ErrNotConnected     = errors.New("tokenvault: no connection for this user and provider")
	ErrScopeNotGranted  = errors.New("tokenvault: connection does not hold the requested scopes")
	ErrReauthRequired   = errors.New("tokenvault: user must reconnect the provider")
	ErrTokenExpired     = errors.New("tokenvault: access token expired and cannot be refreshed")
	ErrRefreshFailed    = errors.New("tokenvault: could not refresh the access token")
	ErrAuditFailed      = errors.New("tokenvault: audit write failed, token withheld")
	ErrDelegationLookup = errors.New("tokenvault: delegation lookup failed")
)

const lockStripes = 64

// Config configures a Vault. Store, Keys, Delegations and Audit are required.
type Config struct {
	Store       theauth.TokenVaultStorage
	Keys        *KeyRing
	Delegations Delegations
	Audit       Auditor
	// Providers maps a provider name to its refresher. A provider without one
	// cannot be refreshed; an expired credential then yields ErrTokenExpired.
	Providers map[string]Refresher
	// ExpirySkew refreshes this long before the stated expiry. Default 60s.
	ExpirySkew time.Duration
	// Clock returns the current time. Default time.Now.
	Clock func() time.Time
}

// Vault is safe for concurrent use.
type Vault struct {
	cfg   Config
	locks [lockStripes]sync.Mutex
}

// New validates cfg and returns a Vault.
func New(cfg Config) (*Vault, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("tokenvault: Store is required")
	case cfg.Keys == nil:
		return nil, errors.New("tokenvault: Keys is required")
	case cfg.Delegations == nil:
		return nil, errors.New("tokenvault: Delegations is required")
	case cfg.Audit == nil:
		return nil, errors.New("tokenvault: Audit is required")
	}
	if cfg.ExpirySkew == 0 {
		cfg.ExpirySkew = 60 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Vault{cfg: cfg}, nil
}

// ConnectInput is a credential the user just authorized at a provider.
type ConnectInput struct {
	UserID       string
	Provider     string
	AccountID    string
	AccessToken  string
	RefreshToken string
	// ExpiresAt is the zero time for a non-expiring access token.
	ExpiresAt time.Time
	Scopes    []string
}

// Connection is the token-free view of a stored credential.
type Connection struct {
	UserID    string
	Provider  string
	AccountID string
	Scopes    []string
	Status    string
	ExpiresAt time.Time
}

// Request asks for an access token for Provider on behalf of UserID.
type Request struct {
	AgentID  string
	UserID   string
	Provider string
	Scopes   []string
}

// AccessToken is what an agent receives. It has no refresh token.
type AccessToken struct {
	Token     string
	TokenType string
	// ExpiresAt is the zero time when the provider gave no expiry.
	ExpiresAt time.Time
	Scopes    []string
}

// String redacts the token so an accidental log line does not leak it.
func (a AccessToken) String() string { return "tokenvault.AccessToken{redacted}" }

// GoString implements fmt.GoStringer.
func (a AccessToken) GoString() string { return a.String() }

func aad(userID, provider, field string) []byte {
	return []byte("tokenvault/v1\x00" + userID + "\x00" + provider + "\x00" + field)
}

func toConnection(c *theauth.VaultCredential) Connection {
	return Connection{
		UserID: c.UserID, Provider: c.Provider, AccountID: c.AccountID,
		Scopes: append([]string(nil), c.Scopes...), Status: c.Status, ExpiresAt: c.AccessExpiresAt,
	}
}

func (v *Vault) emit(ctx context.Context, e Event) error {
	e.At = v.cfg.Clock().UTC()
	return v.cfg.Audit.Record(ctx, e)
}

// Connect stores or replaces the credential for (UserID, Provider), sealed.
func (v *Vault) Connect(ctx context.Context, in ConnectInput) (Connection, error) {
	if in.UserID == "" || in.Provider == "" || in.AccessToken == "" {
		return Connection{}, errors.New("tokenvault: UserID, Provider and AccessToken are required")
	}
	c := theauth.VaultCredential{
		UserID: in.UserID, Provider: in.Provider, AccountID: in.AccountID,
		Scopes: append([]string(nil), in.Scopes...), AccessExpiresAt: in.ExpiresAt,
		Status: theauth.VaultStatusActive,
	}
	var err error
	if c.AccessCT, err = v.cfg.Keys.Seal([]byte(in.AccessToken), aad(in.UserID, in.Provider, "access")); err != nil {
		return Connection{}, err
	}
	if in.RefreshToken != "" {
		if c.RefreshCT, err = v.cfg.Keys.Seal([]byte(in.RefreshToken), aad(in.UserID, in.Provider, "refresh")); err != nil {
			return Connection{}, err
		}
	}
	stored, err := v.cfg.Store.PutVaultCredential(ctx, c)
	if err != nil {
		return Connection{}, fmt.Errorf("tokenvault: store credential: %w", err)
	}
	if err := v.emit(ctx, Event{Action: ActionCredentialStored, UserID: in.UserID, Provider: in.Provider, Scopes: in.Scopes}); err != nil {
		return Connection{}, fmt.Errorf("tokenvault: audit: %w", err)
	}
	return toConnection(&stored), nil
}

// Connections lists a user's connections without any token material.
func (v *Vault) Connections(ctx context.Context, userID string) ([]Connection, error) {
	rows, err := v.cfg.Store.ListVaultCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for i := range rows {
		out = append(out, toConnection(&rows[i]))
	}
	return out, nil
}

// Disconnect deletes the user's credential for provider.
func (v *Vault) Disconnect(ctx context.Context, userID, provider string) error {
	if err := v.cfg.Store.DeleteVaultCredential(ctx, userID, provider); err != nil {
		return err
	}
	return v.emit(ctx, Event{Action: ActionCredentialRemoved, UserID: userID, Provider: provider})
}

// AccessToken returns a usable access token for the agent, after checking the
// delegation and the scopes, refreshing when near expiry. The refresh token
// never leaves the vault. The issuance is audited before the token is
// returned; if the audit write fails no token is returned.
func (v *Vault) AccessToken(ctx context.Context, req Request) (AccessToken, error) {
	tok, err := v.accessToken(ctx, req)
	if err != nil {
		// Best effort: a failing audit sink must not mask the denial.
		_ = v.emit(ctx, Event{Action: ActionTokenDenied, UserID: req.UserID, AgentID: req.AgentID,
			Provider: req.Provider, Scopes: req.Scopes, Reason: reasonOf(err)})
		return AccessToken{}, err
	}
	if err := v.emit(ctx, Event{Action: ActionTokenIssued, UserID: req.UserID, AgentID: req.AgentID,
		Provider: req.Provider, Scopes: req.Scopes}); err != nil {
		return AccessToken{}, ErrAuditFailed
	}
	return tok, nil
}

func (v *Vault) accessToken(ctx context.Context, req Request) (AccessToken, error) {
	if len(req.Scopes) == 0 {
		return AccessToken{}, ErrScopesRequired
	}
	now := v.cfg.Clock()
	ok, err := v.cfg.Delegations.Allows(ctx, req.UserID, req.AgentID, req.Provider, req.Scopes, now)
	if err != nil {
		return AccessToken{}, ErrDelegationLookup
	}
	if !ok {
		return AccessToken{}, ErrNotDelegated
	}
	cred, err := v.cfg.Store.VaultCredentialByUserProvider(ctx, req.UserID, req.Provider)
	if errors.Is(err, storage.ErrNotFound) {
		return AccessToken{}, ErrNotConnected
	}
	if err != nil {
		return AccessToken{}, fmt.Errorf("tokenvault: load credential: %w", err)
	}
	if cred.Status == theauth.VaultStatusNeedsReauth {
		return AccessToken{}, ErrReauthRequired
	}
	if !subset(req.Scopes, cred.Scopes) {
		return AccessToken{}, ErrScopeNotGranted
	}
	if v.stale(cred) {
		if cred, err = v.refresh(ctx, req.UserID, req.Provider); err != nil {
			return AccessToken{}, err
		}
	}
	pt, err := v.cfg.Keys.Open(cred.AccessCT, aad(cred.UserID, cred.Provider, "access"))
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{
		Token: string(pt), TokenType: "Bearer", ExpiresAt: cred.AccessExpiresAt,
		Scopes: append([]string(nil), req.Scopes...),
	}, nil
}

func (v *Vault) stale(c *theauth.VaultCredential) bool {
	return !c.AccessExpiresAt.IsZero() && !c.AccessExpiresAt.After(v.cfg.Clock().Add(v.cfg.ExpirySkew))
}

func (v *Vault) lockFor(userID, provider string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(userID + "\x00" + provider))
	return &v.locks[h.Sum32()%lockStripes]
}

// refresh single-flights per (user, provider) in this process; across nodes the
// version compare and swap decides, and the loser uses the winner's row.
func (v *Vault) refresh(ctx context.Context, userID, provider string) (*theauth.VaultCredential, error) {
	mu := v.lockFor(userID, provider)
	mu.Lock()
	defer mu.Unlock()

	cur, err := v.cfg.Store.VaultCredentialByUserProvider(ctx, userID, provider)
	if err != nil {
		return nil, ErrNotConnected
	}
	if cur.Status == theauth.VaultStatusNeedsReauth {
		return nil, ErrReauthRequired
	}
	if !v.stale(cur) {
		return cur, nil
	}
	refresher := v.cfg.Providers[provider]
	if len(cur.RefreshCT) == 0 || refresher == nil {
		return nil, ErrTokenExpired
	}
	rt, err := v.cfg.Keys.Open(cur.RefreshCT, aad(userID, provider, "refresh"))
	if err != nil {
		return nil, err
	}
	resp, err := refresher.Refresh(ctx, string(rt))
	if errors.Is(err, ErrInvalidGrant) {
		next := *cur
		next.Status = theauth.VaultStatusNeedsReauth
		if _, serr := v.cfg.Store.SwapVaultCredential(ctx, next, cur.Version); serr != nil {
			return nil, ErrRefreshFailed
		}
		_ = v.emit(ctx, Event{Action: ActionReauthRequired, UserID: userID, Provider: provider})
		return nil, ErrReauthRequired
	}
	if err != nil || resp.AccessToken == "" {
		return nil, ErrRefreshFailed
	}
	next := *cur
	if next.AccessCT, err = v.cfg.Keys.Seal([]byte(resp.AccessToken), aad(userID, provider, "access")); err != nil {
		return nil, err
	}
	if resp.RefreshToken != "" {
		if next.RefreshCT, err = v.cfg.Keys.Seal([]byte(resp.RefreshToken), aad(userID, provider, "refresh")); err != nil {
			return nil, err
		}
	}
	if resp.ExpiresIn > 0 {
		next.AccessExpiresAt = v.cfg.Clock().Add(resp.ExpiresIn).UTC()
	} else {
		next.AccessExpiresAt = time.Time{}
	}
	if len(resp.Scopes) > 0 {
		next.Scopes = resp.Scopes
	}
	swapped, err := v.cfg.Store.SwapVaultCredential(ctx, next, cur.Version)
	if err != nil {
		return nil, ErrRefreshFailed
	}
	if !swapped {
		// Another node refreshed first (or the user disconnected). Use its row.
		won, gerr := v.cfg.Store.VaultCredentialByUserProvider(ctx, userID, provider)
		if gerr != nil || v.stale(won) {
			return nil, ErrRefreshFailed
		}
		return won, nil
	}
	_ = v.emit(ctx, Event{Action: ActionCredentialRefresh, UserID: userID, Provider: provider})
	return v.cfg.Store.VaultCredentialByUserProvider(ctx, userID, provider)
}

// Rewrap re-seals every credential still sealed under a non-active key with
// the active key and returns how many rows it moved. Run it after adding a new
// active key; once it reports zero for a retired key, that key can be dropped
// from the ring.
func (v *Vault) Rewrap(ctx context.Context) (int, error) {
	moved, after := 0, ""
	for {
		page, err := v.cfg.Store.ScanVaultCredentials(ctx, after, 100)
		if err != nil {
			return moved, err
		}
		if len(page) == 0 {
			break
		}
		for i := range page {
			after = page[i].ID
			ok, err := v.rewrapOne(ctx, page[i])
			if err != nil {
				return moved, err
			}
			if ok {
				moved++
			}
		}
	}
	if moved > 0 {
		if err := v.emit(ctx, Event{Action: ActionKeysRewrapped, Reason: fmt.Sprintf("rows=%d", moved)}); err != nil {
			return moved, fmt.Errorf("tokenvault: audit: %w", err)
		}
	}
	return moved, nil
}

func (v *Vault) rewrapOne(ctx context.Context, c theauth.VaultCredential) (bool, error) {
	changed := false
	reseal := func(blob []byte, field string) ([]byte, error) {
		if len(blob) == 0 {
			return blob, nil
		}
		id, err := v.cfg.Keys.KeyID(blob)
		if err != nil {
			return nil, err
		}
		if id == v.cfg.Keys.ActiveID() {
			return blob, nil
		}
		pt, err := v.cfg.Keys.Open(blob, aad(c.UserID, c.Provider, field))
		if err != nil {
			return nil, err
		}
		changed = true
		return v.cfg.Keys.Seal(pt, aad(c.UserID, c.Provider, field))
	}
	var err error
	next := c
	if next.AccessCT, err = reseal(c.AccessCT, "access"); err != nil {
		return false, err
	}
	if next.RefreshCT, err = reseal(c.RefreshCT, "refresh"); err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	// A lost swap means a concurrent write already re-sealed it with the active key.
	return v.cfg.Store.SwapVaultCredential(ctx, next, c.Version)
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrScopesRequired):
		return "scopes_required"
	case errors.Is(err, ErrNotDelegated):
		return "not_delegated"
	case errors.Is(err, ErrNotConnected):
		return "not_connected"
	case errors.Is(err, ErrScopeNotGranted):
		return "scope_not_granted"
	case errors.Is(err, ErrReauthRequired):
		return "reauth_required"
	case errors.Is(err, ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, ErrRefreshFailed):
		return "refresh_failed"
	case errors.Is(err, ErrDelegationLookup):
		return "delegation_lookup_failed"
	case errors.Is(err, ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, ErrDecrypt), errors.Is(err, ErrMalformed):
		return "decrypt_failed"
	default:
		return "error"
	}
}

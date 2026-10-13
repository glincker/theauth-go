package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// RefreshProvider is the optional Provider capability behind
// GetProviderToken. RefreshToken exchanges a refresh token for a fresh access
// token (RFC 6749 section 6). It must return an error wrapping
// models.ErrProviderGrantRevoked when the provider rejects the refresh token
// as invalid or revoked. The returned token's RefreshToken is empty when the
// provider does not rotate it; the stored one is then kept.
type RefreshProvider interface {
	Provider
	RefreshToken(ctx context.Context, refreshToken string) (*ProviderToken, error)
}

// TokenStorage is the persistence subset GetProviderToken needs beyond
// Storage.
type TokenStorage interface {
	OAuthAccountsByUserID(ctx context.Context, userID models.ULID) ([]models.OAuthAccount, error)
}

// expirySkew is how long before ExpiresAt a stored access token is already
// treated as expired, so a caller does not receive a token that dies in flight.
const expirySkew = 30 * time.Second

// refreshTimeout bounds one upstream refresh round trip.
const refreshTimeout = 30 * time.Second

// flightGroup collapses concurrent refreshes of one (user, provider) into one
// upstream call.
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done chan struct{}
	tok  ProviderToken
	err  error
}

func (g *flightGroup) do(key string, fn func() (ProviderToken, error)) (ProviderToken, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*flightCall{}
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.tok, c.err
	}
	c := &flightCall{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()

	c.tok, c.err = fn()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(c.done)
	return c.tok, c.err
}

// ProviderToken returns a usable upstream access token for the user's linked
// provider account. A stored token that is still valid is returned as is;
// an expired one is refreshed with the stored refresh token, the rotated
// tokens are persisted, and concurrent callers for the same user and
// provider share one upstream call. Errors wrap ErrProviderNotLinked,
// ErrProviderRefreshUnsupported or ErrProviderGrantRevoked.
//
// Refresh tokens that rotate on every use can race across processes: if two
// processes refresh at once, one of them may be told the grant is revoked.
func (s *Service) ProviderToken(ctx context.Context, userID models.ULID, providerName string) (ProviderToken, error) {
	ts, ok := s.storage.(TokenStorage)
	if !ok {
		return ProviderToken{}, errors.New("theauth: storage cannot list oauth accounts")
	}
	acct, err := findAccount(ctx, ts, userID, providerName)
	if err != nil {
		return ProviderToken{}, err
	}
	if tok, ok := s.usable(acct); ok {
		return tok, nil
	}
	return s.flight.do(userID.String()+"|"+providerName, func() (ProviderToken, error) {
		// Detach from the first caller's cancellation: others wait on this call.
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()
		return s.refresh(bg, ts, userID, providerName)
	})
}

func findAccount(ctx context.Context, ts TokenStorage, userID models.ULID, providerName string) (models.OAuthAccount, error) {
	accts, err := ts.OAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return models.OAuthAccount{}, fmt.Errorf("theauth: list oauth accounts: %w", err)
	}
	for _, a := range accts {
		if a.Provider == providerName {
			return a, nil
		}
	}
	return models.OAuthAccount{}, providerErr(models.CodeProviderNoRefresh, "no linked account for provider "+providerName, models.ErrProviderNotLinked)
}

func providerErr(code, msg string, inner error) error {
	return models.NewError(code, msg, inner)
}

// usable decrypts the stored access token when it is still valid.
func (s *Service) usable(a models.OAuthAccount) (ProviderToken, bool) {
	if len(a.AccessTokenEnc) == 0 {
		return ProviderToken{}, false
	}
	if a.ExpiresAt != nil && !time.Now().Add(expirySkew).Before(*a.ExpiresAt) {
		return ProviderToken{}, false
	}
	plain, err := crypto.Decrypt(s.encKey, a.AccessTokenEnc)
	if err != nil {
		slog.Warn("theauth: decrypt provider access token failed", "provider", a.Provider, "err", err.Error())
		return ProviderToken{}, false
	}
	tok := ProviderToken{AccessToken: string(plain), Scope: a.Scope, TokenType: "Bearer"}
	if a.ExpiresAt != nil {
		tok.ExpiresAt = *a.ExpiresAt
	}
	return tok, true
}

// refresh runs the upstream refresh and persists the rotated tokens.
func (s *Service) refresh(ctx context.Context, ts TokenStorage, userID models.ULID, providerName string) (ProviderToken, error) {
	// Re-read: another caller or process may have refreshed meanwhile.
	acct, err := findAccount(ctx, ts, userID, providerName)
	if err != nil {
		return ProviderToken{}, err
	}
	if tok, ok := s.usable(acct); ok {
		return tok, nil
	}
	if len(acct.RefreshTokenEnc) == 0 {
		if len(acct.AccessTokenEnc) == 0 {
			return ProviderToken{}, providerErr(models.CodeProviderGrantRevoked, "provider grant was revoked, sign in with the provider again", models.ErrProviderGrantRevoked)
		}
		return ProviderToken{}, providerErr(models.CodeProviderNoRefresh, "no refresh token stored for provider "+providerName, models.ErrProviderRefreshUnsupported)
	}
	p, err := s.provider(ctx, providerName)
	if err != nil {
		return ProviderToken{}, err
	}
	rp, ok := p.(RefreshProvider)
	if !ok {
		return ProviderToken{}, providerErr(models.CodeProviderNoRefresh, "provider "+providerName+" cannot refresh tokens", models.ErrProviderRefreshUnsupported)
	}
	oldRefresh, err := crypto.Decrypt(s.encKey, acct.RefreshTokenEnc)
	if err != nil {
		return ProviderToken{}, fmt.Errorf("theauth: decrypt provider refresh token: %w", err)
	}
	fresh, err := rp.RefreshToken(ctx, string(oldRefresh))
	if err != nil {
		if errors.Is(err, models.ErrProviderGrantRevoked) {
			s.clearTokens(ctx, acct)
			s.emitFailure(ctx, providerName, "grant_revoked")
			return ProviderToken{}, providerErr(models.CodeProviderGrantRevoked, "provider grant was revoked, sign in with the provider again", err)
		}
		s.emitFailure(ctx, providerName, "refresh_failed")
		return ProviderToken{}, fmt.Errorf("theauth: refresh %s token: %w", providerName, err)
	}
	if fresh == nil || fresh.AccessToken == "" {
		return ProviderToken{}, fmt.Errorf("theauth: refresh %s token: empty access token", providerName)
	}
	return s.persistRefreshed(ctx, acct, string(oldRefresh), fresh)
}

func (s *Service) persistRefreshed(ctx context.Context, acct models.OAuthAccount, oldRefresh string, fresh *ProviderToken) (ProviderToken, error) {
	accessEnc, err := crypto.Encrypt(s.encKey, []byte(fresh.AccessToken))
	if err != nil {
		return ProviderToken{}, fmt.Errorf("theauth: encrypt access token: %w", err)
	}
	newRefresh := fresh.RefreshToken
	if newRefresh == "" {
		newRefresh = oldRefresh
	}
	refreshEnc, err := crypto.Encrypt(s.encKey, []byte(newRefresh))
	if err != nil {
		return ProviderToken{}, fmt.Errorf("theauth: encrypt refresh token: %w", err)
	}
	scope := fresh.Scope
	if scope == "" {
		scope = acct.Scope
	}
	var expiresAt *time.Time
	if !fresh.ExpiresAt.IsZero() {
		e := fresh.ExpiresAt
		expiresAt = &e
	}
	acct.AccessTokenEnc, acct.RefreshTokenEnc, acct.ExpiresAt, acct.Scope = accessEnc, refreshEnc, expiresAt, scope
	if _, err := s.storage.UpsertOAuthAccount(ctx, acct); err != nil {
		return ProviderToken{}, fmt.Errorf("theauth: persist refreshed provider token: %w", err)
	}
	out := *fresh
	out.RefreshToken = newRefresh
	out.Scope = scope
	if out.TokenType == "" {
		out.TokenType = "Bearer"
	}
	s.auditEm.EmitAudit(ctx, "oauth_account.token_refreshed", models.TargetRef{Type: "oauth_account", ID: acct.ID.String()}, map[string]any{
		"provider": acct.Provider,
	})
	return out, nil
}

// clearTokens drops the stored tokens of a revoked grant so later calls fail
// fast without another upstream round trip.
func (s *Service) clearTokens(ctx context.Context, acct models.OAuthAccount) {
	acct.AccessTokenEnc, acct.RefreshTokenEnc, acct.ExpiresAt = []byte{}, nil, nil
	if _, err := s.storage.UpsertOAuthAccount(ctx, acct); err != nil {
		slog.Warn("theauth: clear revoked provider tokens failed", "provider", acct.Provider, "err", err.Error())
	}
}

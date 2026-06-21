package theauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// oauthStateTTL is how long a state token from /start is considered valid
// at /callback. The OAuth round-trip (user agent -> provider -> redirect)
// rarely exceeds a minute or two; 10 minutes is a comfortable upper bound.
const oauthStateTTL = 10 * time.Minute

// oauthStateGCEvery is how often the GC goroutine sweeps the state map for
// expired entries. Keeping it short caps the worst-case footprint under
// burst load.
const oauthStateGCEvery = time.Minute

// oauthState is the per-flow context stored between /start and /callback.
// Lives in TheAuth.oauthStates keyed by the random state string.
type oauthState struct {
	codeVerifier string
	redirectURI  string
	provider     string
	createdAt    time.Time
}

// oauthStateGCLoop sweeps expired entries from a.oauthStates. Stopped via
// a.Close, which closes a.oauthStateStop.
func (a *TheAuth) oauthStateGCLoop() {
	t := time.NewTicker(oauthStateGCEvery)
	defer t.Stop()
	for {
		select {
		case <-a.oauthStateStop:
			return
		case now := <-t.C:
			cutoff := now.Add(-oauthStateTTL)
			a.oauthStates.Range(func(k, v any) bool {
				if st, ok := v.(*oauthState); ok && st.createdAt.Before(cutoff) {
					a.oauthStates.Delete(k)
				}
				return true
			})
		}
	}
}

// startOAuth generates state + PKCE verifier, records them for the upcoming
// callback, and returns the provider's authorization URL plus the raw state
// string (which the handler also sets as a short-lived cookie for CSRF
// protection). Returns an error when the named provider is not registered.
func (a *TheAuth) startOAuth(_ context.Context, providerName string) (authURL, state string, err error) {
	p, ok := a.providers[providerName]
	if !ok {
		return "", "", fmt.Errorf("theauth: unknown provider %q", providerName)
	}
	state, err = crypto.NewToken()
	if err != nil {
		return "", "", err
	}
	verifier, err := crypto.NewCodeVerifier()
	if err != nil {
		return "", "", err
	}
	challenge := crypto.CodeChallenge(verifier)
	redirectURI := a.baseURL + "/auth/providers/" + providerName + "/callback"
	a.oauthStates.Store(state, &oauthState{
		codeVerifier: verifier,
		redirectURI:  redirectURI,
		provider:     providerName,
		createdAt:    time.Now(),
	})
	authURL = p.AuthURL(state, challenge, redirectURI, nil)
	return authURL, state, nil
}

// callbackOAuth completes the flow: it looks up the state stored at /start,
// exchanges the code, fetches user info, finds-or-creates the local user,
// upserts the OAuthAccount with encrypted tokens, and issues a session.
// Returns the raw session token plus the resolved user. Deletes the state
// entry on success.
func (a *TheAuth) callbackOAuth(ctx context.Context, providerName, code, state, userAgent, ip string) (sessionToken string, user *User, err error) {
	p, ok := a.providers[providerName]
	if !ok {
		return "", nil, fmt.Errorf("theauth: unknown provider %q", providerName)
	}
	raw, ok := a.oauthStates.LoadAndDelete(state)
	if !ok {
		return "", nil, errors.New("theauth: oauth state unknown or expired")
	}
	st, ok := raw.(*oauthState)
	if !ok {
		return "", nil, errors.New("theauth: oauth state corrupted")
	}
	if st.provider != providerName {
		return "", nil, errors.New("theauth: oauth state provider mismatch")
	}
	if time.Since(st.createdAt) > oauthStateTTL {
		return "", nil, errors.New("theauth: oauth state expired")
	}

	tok, err := p.ExchangeCode(ctx, code, st.codeVerifier, st.redirectURI)
	if err != nil {
		return "", nil, fmt.Errorf("theauth: ExchangeCode: %w", err)
	}
	pu, err := p.UserInfo(ctx, tok)
	if err != nil {
		return "", nil, fmt.Errorf("theauth: UserInfo: %w", err)
	}
	if pu == nil || pu.ID == "" {
		return "", nil, errors.New("theauth: provider returned empty user id")
	}

	resolved, err := a.findOrCreateOAuthUser(ctx, providerName, pu)
	if err != nil {
		return "", nil, err
	}

	accessEnc, err := crypto.Encrypt(a.encryptionKey, []byte(tok.AccessToken))
	if err != nil {
		return "", nil, fmt.Errorf("theauth: encrypt access token: %w", err)
	}
	var refreshEnc []byte
	if tok.RefreshToken != "" {
		refreshEnc, err = crypto.Encrypt(a.encryptionKey, []byte(tok.RefreshToken))
		if err != nil {
			return "", nil, fmt.Errorf("theauth: encrypt refresh token: %w", err)
		}
	}
	var expiresAt *time.Time
	if !tok.ExpiresAt.IsZero() {
		e := tok.ExpiresAt
		expiresAt = &e
	}
	now := time.Now()
	if _, err := a.storage.UpsertOAuthAccount(ctx, OAuthAccount{
		ID:              ulid.New(),
		UserID:          resolved.ID,
		Provider:        providerName,
		ProviderUserID:  pu.ID,
		AccessTokenEnc:  accessEnc,
		RefreshTokenEnc: refreshEnc,
		ExpiresAt:       expiresAt,
		Scope:           tok.Scope,
		CreatedAt:       now,
		UpdatedAt:       now,
	}); err != nil {
		return "", nil, fmt.Errorf("theauth: upsert oauth account: %w", err)
	}

	sessToken, _, err := a.issueSession(ctx, *resolved, userAgent, ip)
	if err != nil {
		return "", nil, err
	}
	slog.Info("theauth: oauth signin", "provider", providerName, "user_id", resolved.ID.String())
	return sessToken, resolved, nil
}

// findOrCreateOAuthUser implements the three-branch resolution from the
// design doc: (1) existing oauth_accounts row -> load that user, (2) email
// match -> reuse that user (account-link side effect happens at the call
// site via UpsertOAuthAccount), (3) brand new user.
func (a *TheAuth) findOrCreateOAuthUser(ctx context.Context, providerName string, pu *ProviderUser) (*User, error) {
	// 1) Already linked?
	acct, err := a.storage.OAuthAccountByProviderUserID(ctx, providerName, pu.ID)
	if err == nil && acct != nil {
		u, err := a.storage.UserByID(ctx, acct.UserID)
		if err != nil {
			return nil, fmt.Errorf("theauth: load linked user: %w", err)
		}
		return u, nil
	} else if err != nil && !errors.Is(err, ErrStorageNotFound) {
		return nil, fmt.Errorf("theauth: lookup oauth account: %w", err)
	}

	// 2) Email match?
	if pu.Email != "" {
		u, err := a.storage.UserByEmail(ctx, pu.Email)
		if err == nil && u != nil {
			return u, nil
		}
		if err != nil && !errors.Is(err, ErrStorageNotFound) {
			return nil, fmt.Errorf("theauth: lookup user by email: %w", err)
		}
	}

	// 3) Create.
	now := time.Now()
	newUser := User{
		ID:        ulid.New(),
		Email:     pu.Email,
		Name:      pu.Name,
		AvatarURL: pu.AvatarURL,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if pu.EmailVerified {
		newUser.EmailVerifiedAt = &now
	}
	created, err := a.storage.CreateUser(ctx, newUser)
	if err != nil {
		return nil, fmt.Errorf("theauth: create oauth user: %w", err)
	}
	return &created, nil
}

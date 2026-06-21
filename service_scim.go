package theauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/glincker/theauth-go/internal/ulid"
)

// CreateSCIMToken mints a fresh 256-bit token, stores its sha256 hash, and
// returns the plaintext to the caller. The plaintext is the only point at
// which it leaves the library; subsequent reads only ever see the hash.
func (a *TheAuth) CreateSCIMToken(ctx context.Context, orgID ULID, name string) (string, SCIMToken, error) {
	if a.scimCfg == nil {
		return "", SCIMToken{}, errors.New("theauth: SCIM not enabled")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", SCIMToken{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	rec := SCIMToken{
		ID:             ulid.New(),
		OrganizationID: orgID,
		Name:           name,
		TokenHash:      hash[:],
		CreatedAt:      time.Now(),
	}
	saved, err := a.storage.InsertSCIMToken(ctx, rec)
	if err != nil {
		return "", SCIMToken{}, err
	}
	return token, saved, nil
}

// RevokeSCIMToken marks the named token as revoked. Revoked tokens still
// resolve via SCIMTokenByHash but the middleware refuses them.
func (a *TheAuth) RevokeSCIMToken(ctx context.Context, id ULID) error {
	return a.storage.RevokeSCIMTokenByID(ctx, id, time.Now())
}

// ListSCIMTokens returns every token (revoked or not) for the supplied org.
func (a *TheAuth) ListSCIMTokens(ctx context.Context, orgID ULID) ([]SCIMToken, error) {
	return a.storage.SCIMTokensByOrg(ctx, orgID)
}

// AuthenticateSCIMToken is the entry point invoked by the SCIM bearer
// middleware on every request. Returns the bound organization or an error.
// Touches last_used_at on success.
func (a *TheAuth) AuthenticateSCIMToken(ctx context.Context, presented string) (ULID, error) {
	if presented == "" {
		return ULID{}, ErrInvalidToken
	}
	hash := sha256.Sum256([]byte(presented))
	rec, err := a.storage.SCIMTokenByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, ErrStorageNotFound) {
			return ULID{}, ErrInvalidToken
		}
		return ULID{}, err
	}
	if rec.RevokedAt != nil {
		return ULID{}, ErrInvalidToken
	}
	_ = a.storage.TouchSCIMTokenLastUsed(ctx, rec.ID, time.Now())
	return rec.OrganizationID, nil
}

// scimTokenIDByPresented returns the SCIM token row ID for the supplied
// plaintext token, used for audit actor identification. Returns a zero ULID
// (and no error) when the token is unknown so the audit hook gets a stable
// placeholder rather than a panic.
func (a *TheAuth) scimTokenIDByPresented(ctx context.Context, presented string) ULID {
	if presented == "" {
		return ULID{}
	}
	hash := sha256.Sum256([]byte(presented))
	rec, err := a.storage.SCIMTokenByHash(ctx, hash[:])
	if err != nil || rec == nil {
		return ULID{}
	}
	return rec.ID
}

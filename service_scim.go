package theauth

import (
	"context"
	"errors"

	internalscim "github.com/glincker/theauth-go/internal/scim"
)

// SCIM token service forwarders. PR A architecture reorg (2026-06) moved
// the implementations to internal/scim; the exported method signatures on
// *TheAuth are unchanged (CreateSCIMToken / RevokeSCIMToken /
// ListSCIMTokens / AuthenticateSCIMToken) so consumer code keeps
// compiling. The scimTokenIDByPresented helper (used by middleware_scim)
// also retains its signature.

// CreateSCIMToken mints a fresh 256-bit token, stores its sha256 hash, and
// returns the plaintext to the caller. The plaintext is the only point at
// which it leaves the library; subsequent reads only ever see the hash.
func (a *TheAuth) CreateSCIMToken(ctx context.Context, orgID ULID, name string) (string, SCIMToken, error) {
	token, rec, err := a.scimSvc.CreateToken(ctx, orgID, name)
	if errors.Is(err, internalscim.ErrSCIMDisabled) {
		return "", SCIMToken{}, errors.New("theauth: SCIM not enabled")
	}
	return token, rec, err
}

// RevokeSCIMToken marks the named token as revoked. Revoked tokens still
// resolve via SCIMTokenByHash but the middleware refuses them.
func (a *TheAuth) RevokeSCIMToken(ctx context.Context, id ULID) error {
	return a.scimSvc.RevokeToken(ctx, id)
}

// ListSCIMTokens returns every token (revoked or not) for the supplied org.
func (a *TheAuth) ListSCIMTokens(ctx context.Context, orgID ULID) ([]SCIMToken, error) {
	return a.scimSvc.ListTokens(ctx, orgID)
}

// AuthenticateSCIMToken is the entry point invoked by the SCIM bearer
// middleware on every request. Returns the bound organization or an error.
// Touches last_used_at on success.
func (a *TheAuth) AuthenticateSCIMToken(ctx context.Context, presented string) (ULID, error) {
	return a.scimSvc.Authenticate(ctx, presented)
}

// scimTokenIDByPresented returns the SCIM token row ID for the supplied
// plaintext token, used for audit actor identification. Returns a zero
// ULID (and no error) when the token is unknown so the audit hook gets a
// stable placeholder rather than a panic.
func (a *TheAuth) scimTokenIDByPresented(ctx context.Context, presented string) ULID {
	return a.scimSvc.TokenIDByPresented(ctx, presented)
}

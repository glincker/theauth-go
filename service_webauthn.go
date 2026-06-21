package theauth

import (
	"context"
	"io"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthn forwarders. PR D architecture reorg (2026-06-20) moved the
// implementations to internal/webauthn; the public
// BeginPasskeyRegistration / FinishPasskeyRegistration / BeginPasskeyLogin
// / FinishPasskeyLogin entry points kept their exact signatures so callers
// in this package (handlers_webauthn) continue to compile unchanged.

// BeginPasskeyRegistration starts the registration ceremony for a
// signed-in user.
func (a *TheAuth) BeginPasskeyRegistration(ctx context.Context, userID ULID) (*protocol.CredentialCreation, string, error) {
	return a.webauthnSvc.BeginRegistration(ctx, userID)
}

// FinishPasskeyRegistration completes the registration ceremony.
func (a *TheAuth) FinishPasskeyRegistration(ctx context.Context, userID ULID, challengeToken, name string, body io.Reader) (WebAuthnCredential, error) {
	return a.webauthnSvc.FinishRegistration(ctx, userID, challengeToken, name, body)
}

// BeginPasskeyLogin starts a discoverable-credential login.
func (a *TheAuth) BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return a.webauthnSvc.BeginLogin(ctx)
}

// FinishPasskeyLogin completes a discoverable login.
func (a *TheAuth) FinishPasskeyLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, Session, error) {
	return a.webauthnSvc.FinishLogin(ctx, challengeToken, body, ua, ip)
}

// finishRegistrationFromRequest is a small convenience used by the HTTP
// handler so it can pass an *http.Request rather than re-parsing the
// body. Kept package-internal because the public surface accepts an
// io.Reader to keep the service layer test-friendly.
func (a *TheAuth) finishRegistrationFromRequest(ctx context.Context, userID ULID, challengeToken, name string, r *http.Request) (WebAuthnCredential, error) {
	return a.FinishPasskeyRegistration(ctx, userID, challengeToken, name, http.MaxBytesReader(nil, r.Body, 1<<16))
}

// finishLoginFromRequest mirrors finishRegistrationFromRequest for
// assertions.
func (a *TheAuth) finishLoginFromRequest(ctx context.Context, challengeToken string, r *http.Request, ua, ip string) (string, Session, error) {
	return a.FinishPasskeyLogin(ctx, challengeToken, http.MaxBytesReader(nil, r.Body, 1<<16), ua, ip)
}

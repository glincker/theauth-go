package theauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// webauthnChallengeGCEvery is how often the GC sweep runs. 60s mirrors the
// v0.3 OAuth state GC cadence.
const webauthnChallengeGCEvery = time.Minute

// webauthnChallenge is the in-memory entry stored between /begin and /finish.
// userID is nil for discoverable login (the user is identified by the
// authenticator's userHandle, not known up-front).
type webauthnChallenge struct {
	session   *gowebauthn.SessionData
	userID    *ULID
	expiresAt time.Time
}

// webauthnUser adapts our User row to the upstream webauthn.User interface.
// Credentials carry only the persistence subset; the library reconstructs
// the rest from the assertion at FinishLogin time.
type webauthnUser struct {
	u           User
	credentials []gowebauthn.Credential
}

// WebAuthnID returns the user's 16 raw ULID bytes as the WebAuthn user
// handle. ULID fits well inside the 64 byte handle limit and is stable
// across email or display name renames.
func (w *webauthnUser) WebAuthnID() []byte { id := w.u.ID; return id[:] }

// WebAuthnName is the human-readable identifier (email).
func (w *webauthnUser) WebAuthnName() string { return w.u.Email }

// WebAuthnDisplayName falls back to email when Name is unset.
func (w *webauthnUser) WebAuthnDisplayName() string {
	if w.u.Name != "" {
		return w.u.Name
	}
	return w.u.Email
}

// WebAuthnCredentials returns the registered credentials. May be empty for
// fresh users at registration time; that is normal.
func (w *webauthnUser) WebAuthnCredentials() []gowebauthn.Credential { return w.credentials }

// loadWebauthnUser builds a webauthnUser from storage, materialising the
// existing credential list so the library's exclude-credentials behavior
// prevents re-registering the same authenticator.
func (a *TheAuth) loadWebauthnUser(ctx context.Context, userID ULID) (*webauthnUser, error) {
	u, err := a.storage.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := a.storage.WebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	wu := &webauthnUser{u: *u, credentials: make([]gowebauthn.Credential, 0, len(creds))}
	for _, c := range creds {
		wu.credentials = append(wu.credentials, dbToGoWebauthnCredential(c))
	}
	return wu, nil
}

// dbToGoWebauthnCredential converts our persistent shape into the upstream
// library's runtime shape. Only the fields the library inspects during
// FinishLogin are populated; the others are zero-value safe.
func dbToGoWebauthnCredential(c WebAuthnCredential) gowebauthn.Credential {
	tr := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return gowebauthn.Credential{
		ID:        c.CredentialID,
		PublicKey: c.PublicKey,
		Transport: tr,
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

// webauthnChallengeGCLoop sweeps expired challenge entries. Same pattern as
// the v0.3 oauthStateGCLoop.
func (a *TheAuth) webauthnChallengeGCLoop() {
	t := time.NewTicker(webauthnChallengeGCEvery)
	defer t.Stop()
	for {
		select {
		case <-a.webauthnStop:
			return
		case now := <-t.C:
			a.webauthnChals.Range(func(k, v any) bool {
				if c, ok := v.(*webauthnChallenge); ok && c.expiresAt.Before(now) {
					a.webauthnChals.Delete(k)
				}
				return true
			})
		}
	}
}

// newChallengeToken mints an opaque token used as the cookie value bridging
// /begin and /finish. The token never leaves the server in clear other than
// in the short-lived HttpOnly cookie; we don't accept it in any other shape.
func (a *TheAuth) newChallengeToken() (string, error) {
	return crypto.NewToken()
}

// BeginPasskeyRegistration starts the registration ceremony for a
// signed-in user. Returns the upstream CredentialCreation options for the
// browser to pass to navigator.credentials.create plus the opaque challenge
// token the handler binds in a cookie.
func (a *TheAuth) BeginPasskeyRegistration(ctx context.Context, userID ULID) (*protocol.CredentialCreation, string, error) {
	if a.webauthn == nil {
		return nil, "", errors.New("theauth: WebAuthn not configured")
	}
	wu, err := a.loadWebauthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := a.webauthn.BeginRegistration(wu)
	if err != nil {
		return nil, "", fmt.Errorf("theauth: BeginRegistration: %w", err)
	}
	tok, err := a.newChallengeToken()
	if err != nil {
		return nil, "", err
	}
	uid := userID
	a.webauthnChals.Store(tok, &webauthnChallenge{
		session:   session,
		userID:    &uid,
		expiresAt: time.Now().Add(a.webauthnChalTTL),
	})
	return creation, tok, nil
}

// FinishPasskeyRegistration completes the registration ceremony. The body
// is the raw JSON the browser POSTs from navigator.credentials.create.
// On success the new row is inserted and returned to the caller for display
// (nickname, AAGUID, transports). Single-use: the challenge entry is
// removed before the library is invoked so a failed verify burns it.
func (a *TheAuth) FinishPasskeyRegistration(ctx context.Context, userID ULID, challengeToken, name string, body io.Reader) (WebAuthnCredential, error) {
	if a.webauthn == nil {
		return WebAuthnCredential{}, errors.New("theauth: WebAuthn not configured")
	}
	raw, ok := a.webauthnChals.LoadAndDelete(challengeToken)
	if !ok {
		return WebAuthnCredential{}, NewError(CodeWebAuthn, "challenge unknown or expired", nil)
	}
	chal, ok := raw.(*webauthnChallenge)
	if !ok || chal.userID == nil || *chal.userID != userID {
		return WebAuthnCredential{}, NewError(CodeWebAuthn, "challenge user mismatch", nil)
	}
	if time.Now().After(chal.expiresAt) {
		return WebAuthnCredential{}, NewError(CodeWebAuthn, "challenge expired", nil)
	}
	wu, err := a.loadWebauthnUser(ctx, userID)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return WebAuthnCredential{}, NewError(CodeWebAuthn, "invalid attestation body", err)
	}
	cred, err := a.webauthn.CreateCredential(wu, *chal.session, parsed)
	if err != nil {
		return WebAuthnCredential{}, NewError(CodeWebAuthn, "create credential failed", err)
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	now := time.Now()
	row := WebAuthnCredential{
		ID:           ulid.New(),
		UserID:       userID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		AAGUID:       cred.Authenticator.AAGUID,
		Name:         name,
		CreatedAt:    now,
	}
	stored, err := a.storage.InsertWebAuthnCredential(ctx, row)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("theauth: insert webauthn credential: %w", err)
	}
	slog.Info("theauth: webauthn registered", "user_id", userID.String(), "credential_id_len", len(stored.CredentialID))
	return stored, nil
}

// BeginPasskeyLogin starts a discoverable-credential login. The user is not
// identified up-front; the authenticator returns its userHandle inside the
// assertion, which we look up in FinishPasskeyLogin.
func (a *TheAuth) BeginPasskeyLogin(_ context.Context) (*protocol.CredentialAssertion, string, error) {
	if a.webauthn == nil {
		return nil, "", errors.New("theauth: WebAuthn not configured")
	}
	assertion, session, err := a.webauthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("theauth: BeginDiscoverableLogin: %w", err)
	}
	tok, err := a.newChallengeToken()
	if err != nil {
		return nil, "", err
	}
	a.webauthnChals.Store(tok, &webauthnChallenge{
		session:   session,
		expiresAt: time.Now().Add(a.webauthnChalTTL),
	})
	return assertion, tok, nil
}

// FinishPasskeyLogin completes a discoverable login. The handler hands us
// the browser's JSON, the challenge token, and the request metadata. On
// success we issue a full session directly: per NIST SP 800-63B rev 4, a
// passkey login is a single strong factor that satisfies AAL2 by itself,
// so we do not gate it on a second TOTP step (single-factor-strong model).
// See https://pages.nist.gov/800-63-4/sp800-63b.html .
func (a *TheAuth) FinishPasskeyLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, Session, error) {
	if a.webauthn == nil {
		return "", Session{}, errors.New("theauth: WebAuthn not configured")
	}
	raw, ok := a.webauthnChals.LoadAndDelete(challengeToken)
	if !ok {
		return "", Session{}, NewError(CodeWebAuthn, "challenge unknown or expired", nil)
	}
	chal, ok := raw.(*webauthnChallenge)
	if !ok {
		return "", Session{}, NewError(CodeWebAuthn, "challenge corrupted", nil)
	}
	if time.Now().After(chal.expiresAt) {
		return "", Session{}, NewError(CodeWebAuthn, "challenge expired", nil)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return "", Session{}, NewError(CodeWebAuthn, "invalid assertion body", err)
	}
	// Discoverable login: the library calls our handler with the authenticator's
	// rawID and userHandle. We use userHandle (which is our ULID bytes) to load
	// the owning user and their credentials.
	handler := func(_, userHandle []byte) (gowebauthn.User, error) {
		if len(userHandle) != 16 {
			return nil, errors.New("theauth: unexpected user handle length")
		}
		var uid ULID
		copy(uid[:], userHandle)
		wu, err := a.loadWebauthnUser(ctx, uid)
		if err != nil {
			return nil, err
		}
		return wu, nil
	}
	cred, err := a.webauthn.ValidateDiscoverableLogin(handler, *chal.session, parsed)
	if err != nil {
		return "", Session{}, NewError(CodeWebAuthn, "validate assertion failed", err)
	}
	// Look up the credential row by ID so we know which user to log in (and
	// can update the sign count).
	stored, err := a.storage.WebAuthnCredentialByCredentialID(ctx, cred.ID)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: lookup credential: %w", err)
	}
	user, err := a.storage.UserByID(ctx, stored.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: lookup user: %w", err)
	}
	// Replay protection: bump the stored sign count, but tolerate the
	// 0-stays-0 carve-out the WebAuthn spec mandates for authenticators
	// that do not implement counters.
	newCount := cred.Authenticator.SignCount
	if newCount > stored.SignCount {
		if err := a.storage.UpdateWebAuthnSignCount(ctx, stored.CredentialID, newCount, time.Now()); err != nil {
			return "", Session{}, fmt.Errorf("theauth: update sign count: %w", err)
		}
	} else if !(newCount == 0 && stored.SignCount == 0) {
		// Equal-non-zero or lower: clone warning per spec.
		return "", Session{}, ErrReplayDetected
	}
	sessTok, sess, err := a.issueSession(ctx, *user, ua, ip)
	if err != nil {
		return "", Session{}, err
	}
	slog.Info("theauth: passkey login", "user_id", user.ID.String(), "credential_id_len", len(stored.CredentialID))
	return sessTok, sess, nil
}

// finishRegistrationFromRequest is a small convenience used by the HTTP
// handler so it can pass an *http.Request rather than re-parsing the body.
// Kept package-internal because the public surface accepts an io.Reader to
// keep the service layer test-friendly.
func (a *TheAuth) finishRegistrationFromRequest(ctx context.Context, userID ULID, challengeToken, name string, r *http.Request) (WebAuthnCredential, error) {
	return a.FinishPasskeyRegistration(ctx, userID, challengeToken, name, http.MaxBytesReader(nil, r.Body, 1<<16))
}

// finishLoginFromRequest mirrors finishRegistrationFromRequest for assertions.
func (a *TheAuth) finishLoginFromRequest(ctx context.Context, challengeToken string, r *http.Request, ua, ip string) (string, Session, error) {
	return a.FinishPasskeyLogin(ctx, challengeToken, http.MaxBytesReader(nil, r.Body, 1<<16), ua, ip)
}

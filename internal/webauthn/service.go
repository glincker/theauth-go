// Package webauthn owns the v0.5 passkey (FIDO2 / WebAuthn L3) surface:
// registration ceremonies (BeginRegistration + FinishRegistration), login
// ceremonies (BeginLogin + FinishLogin), the in-memory sync.Map for
// in-flight challenges, and the GC goroutine that sweeps expired
// challenges.
//
// Extracted from root service_webauthn.go in PR D of the 2026-06
// architecture reorg. The root *theauth.TheAuth holds a *Service and
// exposes BeginPasskeyRegistration / FinishPasskeyRegistration /
// BeginPasskeyLogin / FinishPasskeyLogin as thin forwarders so the v0.5
// public surface is unchanged.
//
// The challenge map (challenges) lives on the Service. The GC goroutine
// for expired challenges starts in Start and stops in Stop; every "go ..."
// in this package has a matching stop path so there is no goroutine leak.
//
// FinishPasskeyLogin mints a session via the injected SessionIssuer; the
// concrete *session.Service satisfies this interface naturally so this
// package does not import internal/session.
package webauthn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// challengeGCEvery is how often the GC sweep runs. 60s mirrors the v0.3
// OAuth state GC cadence.
const challengeGCEvery = time.Minute

// challenge is the in-memory entry stored between /begin and /finish.
// userID is nil for discoverable login (the user is identified by the
// authenticator's userHandle, not known up-front).
type challenge struct {
	session   *gowebauthn.SessionData
	userID    *models.ULID
	expiresAt time.Time
}

// webauthnUser adapts our User row to the upstream webauthn.User interface.
// Credentials carry only the persistence subset; the library reconstructs
// the rest from the assertion at FinishLogin time.
type webauthnUser struct {
	u           models.User
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

// Storage is the minimal persistence subset this package needs.
type Storage interface {
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
	InsertWebAuthnCredential(ctx context.Context, c models.WebAuthnCredential) (models.WebAuthnCredential, error)
	WebAuthnCredentialsByUserID(ctx context.Context, userID models.ULID) ([]models.WebAuthnCredential, error)
	WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error
}

// SessionIssuer abstracts the session.Issue call so FinishLogin can mint a
// session without importing internal/session.
type SessionIssuer interface {
	Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error)
}

// Config bundles the runtime knobs for the WebAuthn service. Mirrors the
// root theauth.WebAuthnConfig field set the Service actually consumes.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	ChallengeTTL  time.Duration
}

// ErrReplayDetected is returned when a sign-count update receives a value
// not strictly greater than the stored one. Re-exported via root
// errors.go.
var ErrReplayDetected = errors.New("theauth: webauthn sign count replay detected")

// Service holds the dependencies needed for WebAuthn flows.
type Service struct {
	storage  Storage
	sessions SessionIssuer
	auditEm  audit.Emitter
	wa       *gowebauthn.WebAuthn
	cfg      *Config

	// challenges is the in-memory map of in-flight challenges keyed by
	// the opaque token returned from BeginRegistration / BeginLogin.
	challenges sync.Map

	// stopGC signals the challenge GC goroutine to exit. nil before
	// Start; closed by Stop.
	stopGC  chan struct{}
	started bool
	stopped bool
	mu      sync.Mutex // guards started / stopped / stopGC
}

// NewService constructs a WebAuthn Service. cfg may be nil; in that case
// every public method returns "WebAuthn not configured" matching the
// legacy root behavior. em may be nil; the constructor swaps in
// audit.NoopEmitter.
//
// NewService instantiates the upstream go-webauthn instance when cfg is
// non-nil. Returns an error when the upstream config is invalid.
func NewService(storage Storage, sessions SessionIssuer, em audit.Emitter, cfg *Config) (*Service, error) {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	s := &Service{
		storage:  storage,
		sessions: sessions,
		auditEm:  em,
		cfg:      cfg,
	}
	if cfg == nil {
		return s, nil
	}
	display := cfg.RPDisplayName
	if display == "" {
		display = cfg.RPID
	}
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         display,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: "none",
	})
	if err != nil {
		return nil, fmt.Errorf("theauth: webauthn config: %w", err)
	}
	s.wa = wa
	return s, nil
}

// Start spawns the challenge GC goroutine. Idempotent: a second call is a
// no-op. No-op when cfg is nil.
func (s *Service) Start() {
	if s.cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	s.stopGC = make(chan struct{})
	go s.gcLoop(s.stopGC)
}

// Stop closes the stop channel and signals the GC goroutine to return.
// Idempotent: a second call is a no-op.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped {
		return
	}
	s.stopped = true
	if s.stopGC != nil {
		select {
		case <-s.stopGC:
		default:
			close(s.stopGC)
		}
	}
}

// gcLoop sweeps expired challenge entries.
func (s *Service) gcLoop(stop chan struct{}) {
	t := time.NewTicker(challengeGCEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.challenges.Range(func(k, v any) bool {
				if c, ok := v.(*challenge); ok && c.expiresAt.Before(now) {
					s.challenges.Delete(k)
				}
				return true
			})
		}
	}
}

// loadWebauthnUser builds a webauthnUser from storage, materialising the
// existing credential list so the library's exclude-credentials behavior
// prevents re-registering the same authenticator.
func (s *Service) loadWebauthnUser(ctx context.Context, userID models.ULID) (*webauthnUser, error) {
	u, err := s.storage.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := s.storage.WebAuthnCredentialsByUserID(ctx, userID)
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
func dbToGoWebauthnCredential(c models.WebAuthnCredential) gowebauthn.Credential {
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

// newChallengeToken mints an opaque token used as the cookie value
// bridging /begin and /finish. The token never leaves the server in clear
// other than in the short-lived HttpOnly cookie; we do not accept it in
// any other shape.
func (s *Service) newChallengeToken() (string, error) {
	return crypto.NewToken()
}

// BeginRegistration starts the registration ceremony for a signed-in
// user. Returns the upstream CredentialCreation options for the browser
// to pass to navigator.credentials.create plus the opaque challenge token
// the handler binds in a cookie.
func (s *Service) BeginRegistration(ctx context.Context, userID models.ULID) (*protocol.CredentialCreation, string, error) {
	if s.wa == nil {
		return nil, "", errors.New("theauth: WebAuthn not configured")
	}
	wu, err := s.loadWebauthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.wa.BeginRegistration(wu)
	if err != nil {
		return nil, "", fmt.Errorf("theauth: BeginRegistration: %w", err)
	}
	tok, err := s.newChallengeToken()
	if err != nil {
		return nil, "", err
	}
	uid := userID
	s.challenges.Store(tok, &challenge{
		session:   session,
		userID:    &uid,
		expiresAt: time.Now().Add(s.cfg.ChallengeTTL),
	})
	return creation, tok, nil
}

// FinishRegistration completes the registration ceremony. The body is the
// raw JSON the browser POSTs from navigator.credentials.create. On success
// the new row is inserted and returned to the caller for display
// (nickname, AAGUID, transports). Single-use: the challenge entry is
// removed before the library is invoked so a failed verify burns it.
func (s *Service) FinishRegistration(ctx context.Context, userID models.ULID, challengeToken, name string, body io.Reader) (models.WebAuthnCredential, error) {
	if s.wa == nil {
		return models.WebAuthnCredential{}, errors.New("theauth: WebAuthn not configured")
	}
	raw, ok := s.challenges.LoadAndDelete(challengeToken)
	if !ok {
		return models.WebAuthnCredential{}, models.NewError(models.CodeWebAuthn, "challenge unknown or expired", nil)
	}
	chal, ok := raw.(*challenge)
	if !ok || chal.userID == nil || *chal.userID != userID {
		return models.WebAuthnCredential{}, models.NewError(models.CodeWebAuthn, "challenge user mismatch", nil)
	}
	if time.Now().After(chal.expiresAt) {
		return models.WebAuthnCredential{}, models.NewError(models.CodeWebAuthn, "challenge expired", nil)
	}
	wu, err := s.loadWebauthnUser(ctx, userID)
	if err != nil {
		return models.WebAuthnCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return models.WebAuthnCredential{}, models.NewError(models.CodeWebAuthn, "invalid attestation body", err)
	}
	cred, err := s.wa.CreateCredential(wu, *chal.session, parsed)
	if err != nil {
		return models.WebAuthnCredential{}, models.NewError(models.CodeWebAuthn, "create credential failed", err)
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	now := time.Now()
	row := models.WebAuthnCredential{
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
	stored, err := s.storage.InsertWebAuthnCredential(ctx, row)
	if err != nil {
		return models.WebAuthnCredential{}, fmt.Errorf("theauth: insert webauthn credential: %w", err)
	}
	s.auditEm.EmitAudit(ctx, "passkey.registered", models.TargetRef{Type: "webauthn_credential", ID: stored.ID.String()}, map[string]any{
		"aaguid": fmt.Sprintf("%x", stored.AAGUID),
	})
	slog.Info("theauth: webauthn registered", "user_id", userID.String(), "credential_id_len", len(stored.CredentialID))
	return stored, nil
}

// BeginLogin starts a discoverable-credential login. The user is not
// identified up-front; the authenticator returns its userHandle inside
// the assertion, which we look up in FinishLogin.
func (s *Service) BeginLogin(_ context.Context) (*protocol.CredentialAssertion, string, error) {
	if s.wa == nil {
		return nil, "", errors.New("theauth: WebAuthn not configured")
	}
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("theauth: BeginDiscoverableLogin: %w", err)
	}
	tok, err := s.newChallengeToken()
	if err != nil {
		return nil, "", err
	}
	s.challenges.Store(tok, &challenge{
		session:   session,
		expiresAt: time.Now().Add(s.cfg.ChallengeTTL),
	})
	return assertion, tok, nil
}

// FinishLogin completes a discoverable login. The handler hands us the
// browser's JSON, the challenge token, and the request metadata. On
// success we issue a full session directly: per NIST SP 800-63B rev 4, a
// passkey login is a single strong factor that satisfies AAL2 by itself,
// so we do not gate it on a second TOTP step (single-factor-strong
// model). See https://pages.nist.gov/800-63-4/sp800-63b.html .
func (s *Service) FinishLogin(ctx context.Context, challengeToken string, body io.Reader, ua, ip string) (string, models.Session, error) {
	if s.wa == nil {
		return "", models.Session{}, errors.New("theauth: WebAuthn not configured")
	}
	raw, ok := s.challenges.LoadAndDelete(challengeToken)
	if !ok {
		return "", models.Session{}, models.NewError(models.CodeWebAuthn, "challenge unknown or expired", nil)
	}
	chal, ok := raw.(*challenge)
	if !ok {
		return "", models.Session{}, models.NewError(models.CodeWebAuthn, "challenge corrupted", nil)
	}
	if time.Now().After(chal.expiresAt) {
		return "", models.Session{}, models.NewError(models.CodeWebAuthn, "challenge expired", nil)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return "", models.Session{}, models.NewError(models.CodeWebAuthn, "invalid assertion body", err)
	}
	// Discoverable login: the library calls our handler with the
	// authenticator's rawID and userHandle. We use userHandle (which is
	// our ULID bytes) to load the owning user and their credentials.
	handler := func(_, userHandle []byte) (gowebauthn.User, error) {
		if len(userHandle) != 16 {
			return nil, errors.New("theauth: unexpected user handle length")
		}
		var uid models.ULID
		copy(uid[:], userHandle)
		wu, err := s.loadWebauthnUser(ctx, uid)
		if err != nil {
			return nil, err
		}
		return wu, nil
	}
	cred, err := s.wa.ValidateDiscoverableLogin(handler, *chal.session, parsed)
	if err != nil {
		return "", models.Session{}, models.NewError(models.CodeWebAuthn, "validate assertion failed", err)
	}
	stored, err := s.storage.WebAuthnCredentialByCredentialID(ctx, cred.ID)
	if err != nil {
		return "", models.Session{}, fmt.Errorf("theauth: lookup credential: %w", err)
	}
	user, err := s.storage.UserByID(ctx, stored.UserID)
	if err != nil {
		return "", models.Session{}, fmt.Errorf("theauth: lookup user: %w", err)
	}
	// Replay protection: bump the stored sign count, but tolerate the
	// 0-stays-0 carve-out the WebAuthn spec mandates for authenticators
	// that do not implement counters.
	newCount := cred.Authenticator.SignCount
	if newCount > stored.SignCount {
		if err := s.storage.UpdateWebAuthnSignCount(ctx, stored.CredentialID, newCount, time.Now()); err != nil {
			return "", models.Session{}, fmt.Errorf("theauth: update sign count: %w", err)
		}
	} else if newCount != 0 || stored.SignCount != 0 {
		// Equal-non-zero or lower: clone warning per spec.
		return "", models.Session{}, ErrReplayDetected
	}
	sessTok, sess, err := s.sessions.Issue(ctx, *user, ua, ip)
	if err != nil {
		return "", models.Session{}, err
	}
	slog.Info("theauth: passkey login", "user_id", user.ID.String(), "credential_id_len", len(stored.CredentialID))
	return sessTok, sess, nil
}

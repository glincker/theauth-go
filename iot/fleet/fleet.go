// Package fleet is the Go twin of the TypeScript device conformance kit (@glinr/theauth/testing/devices).
// It simulates N devices against a real in process theauth-go authorization server and the real HTTP
// handlers with a deterministic virtual clock: devices enroll with a bulk join token and their own
// ES256 key, mint tokens with the RFC 7523 assertion grant, fetch offline policy bundles and revocation
// snapshots, decide offline, drift in time, go offline and get revoked mid session.
//
// What differs from the TypeScript kit, on purpose:
//   - The Go authorization server mints scoped access tokens (it has no per action authorize route), so
//     the "assertion" scenario checks the token endpoint: a granted scope gets a token, an ungranted
//     scope is refused with invalid_scope.
//   - Offline policy bundles and revocation snapshots are issued by the TypeScript core in production. The
//     kit plays the part of a Go gateway that acts as a local issuer (iot/device Signer), behind the same
//     assertion check, with the same bundle format, so the device side code under test is the real one.
//
// Nothing here imports testing. The virtual clock is the Clock of the authorization server only: it does
// not replace time.Now process wide, so never reuse the fleet's server in a long running service.
package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/iot/device"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// Names the simulated server uses. The issuer is a reserved example domain: the in process server
// is reached through its test address, and the issuer only appears inside tokens.
const (
	Issuer   = "https://auth.example.com"
	Resource = "https://iot.example.com/api"
	// BundleKID is the key id of the kit's bundle issuer.
	BundleKID = "fleet-bundle"
	// ScopeGranted is a scope every simulated device holds, ScopeDenied one no device holds.
	ScopeGranted = "telemetry:write"
	ScopeDenied  = "admin"
)

// Options configure New.
type Options struct {
	// Size is the number of devices. Default 100.
	Size int
	// Concurrency is how many devices act at once. Default 25.
	Concurrency int
	// Start is the virtual start time. Default DefaultStart.
	Start time.Time
	// BundleTTL is the lifetime of bundles and snapshots. Default one hour.
	BundleTTL time.Duration
}

// Fleet is a running simulation. Close it when done.
type Fleet struct {
	Clock   *VirtualClock
	Latency *Recorder
	Devices []*Device
	// OwnerID is the organization that owns every device.
	OwnerID theauth.ULID

	auth        *theauth.TheAuth
	store       *memory.Store
	srv         *httptest.Server
	client      *http.Client
	concurrency int
	bundleTTL   time.Duration
	issuer      *device.Signer
	bundleKeys  *device.KeySet

	mu      sync.Mutex
	blocked map[string]bool
}

// New builds the authorization server and enrolls Size devices through the real enrollment routes.
func New(ctx context.Context, opts Options) (*Fleet, error) {
	if opts.Size < 1 {
		opts.Size = 100
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 25
	}
	if opts.BundleTTL <= 0 {
		opts.BundleTTL = time.Hour
	}
	clock := NewVirtualClock(opts.Start)
	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		return nil, err
	}
	store := memory.New()
	auth, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       Issuer,
		EncryptionKey: enc,
		// The handlers rate limit per client address. Devices reach the server over loopback, so loopback is a
		// trusted proxy and each device presents its own address in X-Forwarded-For, like a device on its own link.
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: Issuer,
			Resources: []theauth.ProtectedResource{
				{Identifier: Resource, Scopes: []string{ScopeGranted, "config:read", ScopeDenied}},
			},
			DisableRotation: true,
			Clock:           clock,
			DeviceTokens:    &theauth.DeviceTokensConfig{EnrollPerMinute: -1, TokenPerMinute: -1},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("fleet: build server: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := device.NewSigner(priv, nil)
	if err != nil {
		return nil, err
	}
	pub := signer.Public()
	pub.KID = BundleKID

	f := &Fleet{
		Clock: clock, Latency: NewRecorder(), OwnerID: newULID(), auth: auth, store: store,
		concurrency: opts.Concurrency, bundleTTL: opts.BundleTTL, issuer: signer,
		bundleKeys: device.NewKeySet(pub), blocked: map[string]bool{},
		client: &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 128, MaxConnsPerHost: 128}},
	}
	r := chi.NewRouter()
	auth.Mount(r)
	r.Get("/device/bundle", f.serveBundle)
	f.srv = httptest.NewServer(r)

	_, secret, err := auth.CreateDeviceJoinToken(ctx, theauth.CreateDeviceJoinTokenInput{
		OrganizationID: &f.OwnerID, Name: "fleet", Scopes: []string{ScopeGranted, "config:read"},
		Kind: theauth.DeviceJoinTokenBulk, MaxUses: opts.Size, TTL: 24 * time.Hour,
	})
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("fleet: join token: %w", err)
	}
	f.Devices = make([]*Device, opts.Size)
	for i := range f.Devices {
		f.Devices[i] = newDevice(i, f)
	}
	var mu sync.Mutex
	var firstErr error
	forEach(ctx, f.Devices, f.concurrency, func(d *Device) {
		if err := f.Latency.timeErr("enroll", func() error { return d.Enroll(ctx, secret) }); err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = fmt.Errorf("device %d: %w", d.Index, err)
			}
			mu.Unlock()
		}
	})
	if firstErr != nil {
		f.Close()
		return nil, firstErr
	}
	return f, nil
}

func (r *Recorder) timeErr(name string, f func() error) error {
	start := time.Now()
	err := f()
	r.Record(name, time.Since(start))
	return err
}

// Close stops the server and releases connections.
func (f *Fleet) Close() {
	f.client.CloseIdleConnections()
	f.srv.Close()
	f.auth.Close()
}

// URL is the address of the in process server, for a device implementation under test.
func (f *Fleet) URL() string { return f.srv.URL }

// JWKS returns the keys that verify the bundles and snapshots the fleet issues.
func (f *Fleet) JWKS() *device.KeySet { return f.bundleKeys }

// ForEach runs task for every device with the fleet's concurrency.
func (f *Fleet) ForEach(ctx context.Context, task func(*Device)) {
	forEach(ctx, f.Devices, f.concurrency, task)
}

func (f *Fleet) setBlocked(id string, blocked bool) {
	f.mu.Lock()
	if blocked {
		f.blocked[id] = true
	} else {
		delete(f.blocked, id)
	}
	f.mu.Unlock()
}

func (f *Fleet) blockedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.blocked))
	for id := range f.blocked {
		out = append(out, id)
	}
	return out
}

func parseID(s string) (theauth.ULID, error) { return parseULID(s) }

// Revoke revokes a device for good. The server stops it at once and the next snapshot lists it.
func (f *Fleet) Revoke(ctx context.Context, d *Device) error {
	id, err := parseID(d.ID)
	if err != nil {
		return err
	}
	if err := f.auth.RevokeDevice(ctx, id); err != nil {
		return err
	}
	f.setBlocked(d.ID, true)
	return nil
}

// Suspend pauses a device. Resume reverses it.
func (f *Fleet) Suspend(ctx context.Context, d *Device) error {
	id, err := parseID(d.ID)
	if err != nil {
		return err
	}
	if err := f.auth.SuspendDevice(ctx, id); err != nil {
		return err
	}
	f.setBlocked(d.ID, true)
	return nil
}

// Resume lifts a suspension.
func (f *Fleet) Resume(ctx context.Context, d *Device) error {
	id, err := parseID(d.ID)
	if err != nil {
		return err
	}
	if err := f.auth.ResumeDevice(ctx, id); err != nil {
		return err
	}
	f.setBlocked(d.ID, false)
	return nil
}

// errNoDevice marks a bundle request for a device the server does not know or that is not active.
var errNoDevice = errors.New("fleet: device not active")

// serveBundle is the kit's local bundle issuer: the same assertion check a gateway would run, then a
// signed bundle and revocation snapshot. 401 for any credential problem or a blocked device.
func (f *Fleet) serveBundle(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	id, key, err := f.deviceKeyFor(r.Context(), token)
	if err != nil || device.VerifyAssertion(token, key, id, Issuer+"/oauth/token", f.Clock.Now()) != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := f.Clock.Now()
	owner := f.OwnerID.String()
	tok, err := f.issuer.SignBundle(BundleKID, device.Claims{
		Issuer: device.DefaultIssuer, Subject: id, Audience: id, IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Exp: now.Add(f.bundleTTL).Unix(), JTI: newULID().String(), Seq: now.UnixMilli(), Owner: owner,
		Perms: []device.Permission{
			{Resource: "mqtt:sensors:*", Actions: []string{"publish"}},
			{Resource: "mqtt:cmd:" + id, Actions: []string{"subscribe"}},
		},
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	snap, err := f.issuer.SignRevocations(BundleKID, device.DefaultIssuer, owner, f.blockedIDs(), now, f.bundleTTL)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"token": tok, "revocations": map[string]any{"token": snap}})
}

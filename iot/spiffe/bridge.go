package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
)

// DeviceLookup is the part of the device registry the bridge needs. theauth.DeviceIdentityStorage
// satisfies it (DeviceBySPIFFEID), and so does every bundled storage backend.
type DeviceLookup interface {
	DeviceBySPIFFEID(ctx context.Context, spiffeID string) (*theauth.Device, error)
}

// Config configures a Bridge.
type Config struct {
	// TrustDomains holds the trust bundle of each trust domain you accept.
	TrustDomains map[string]TrustDomainConfig
	// Audience lists the values a JWT-SVID may carry. Empty refuses JWT-SVIDs.
	Audience []string
	// Devices maps verified SPIFFE IDs to devices. Without it nothing resolves.
	Devices DeviceLookup
	// Now is the time source, default time.Now.
	Now func() time.Time
	// ClockSkew defaults to 30s. MaxX509Lifetime refuses longer lived X.509-SVIDs (zero: no limit).
	ClockSkew       time.Duration
	MaxX509Lifetime time.Duration
	// MaxJWTTTL is the longest accepted JWT-SVID expiry from now, default 1h.
	MaxJWTTTL time.Duration
}

// Result is a verified workload mapped to a device.
type Result struct {
	Device   theauth.Device
	SPIFFEID string
	// Kind is "x509" or "jwt".
	Kind      string
	ExpiresAt time.Time
	// CNF is the RFC 8705 confirmation member for an X.509-SVID: {"x5t#S256": thumbprint}. Nil for a JWT-SVID.
	CNF map[string]string
}

// Bridge verifies SVIDs and resolves them to existing devices. Nothing is created on the fly.
type Bridge struct {
	cfg   Config
	Store *Store
}

// New builds a Bridge. It fails on a bad trust domain configuration so a typo is found at startup.
func New(cfg Config) (*Bridge, error) {
	store, err := NewStore(cfg.TrustDomains, cfg.Now)
	if err != nil {
		return nil, err
	}
	return &Bridge{cfg: cfg, Store: store}, nil
}

func (b *Bridge) now() time.Time {
	if b.cfg.Now != nil {
		return b.cfg.Now()
	}
	return time.Now()
}

// AuthenticateX509 verifies a leaf-first chain taken from a verified TLS handshake and resolves it.
func (b *Bridge) AuthenticateX509(ctx context.Context, chain []*x509.Certificate) (*Result, *Error) {
	id, ferr := VerifyX509(ctx, chain, b.Store, X509Options{
		Now:         b.now(),
		ClockSkew:   b.cfg.ClockSkew,
		MaxLifetime: b.cfg.MaxX509Lifetime,
	})
	if ferr != nil {
		return nil, ferr
	}
	dev, ferr := b.resolve(ctx, id.ID.String)
	if ferr != nil {
		return nil, ferr
	}
	return &Result{
		Device: *dev, SPIFFEID: id.ID.String, Kind: "x509", ExpiresAt: id.NotAfter,
		CNF: map[string]string{"x5t#S256": id.Thumbprint},
	}, nil
}

// AuthenticatePEM is AuthenticateX509 for a PEM encoded chain.
func (b *Bridge) AuthenticatePEM(ctx context.Context, chainPEM []byte) (*Result, *Error) {
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fail(CodeMalformed, "certificate could not be parsed")
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fail(CodeMalformed, "no certificate in the chain")
	}
	return b.AuthenticateX509(ctx, chain)
}

// AuthenticateJWT verifies a JWT-SVID and resolves it.
func (b *Bridge) AuthenticateJWT(ctx context.Context, token string) (*Result, *Error) {
	id, ferr := VerifyJWT(ctx, token, b.Store, JWTOptions{
		Audience:  b.cfg.Audience,
		Now:       b.now(),
		ClockSkew: b.cfg.ClockSkew,
		MaxTTL:    b.cfg.MaxJWTTTL,
	})
	if ferr != nil {
		return nil, ferr
	}
	dev, ferr := b.resolve(ctx, id.ID.String)
	if ferr != nil {
		return nil, ferr
	}
	return &Result{Device: *dev, SPIFFEID: id.ID.String, Kind: "jwt", ExpiresAt: id.ExpiresAt}, nil
}

func (b *Bridge) resolve(ctx context.Context, spiffeID string) (*theauth.Device, *Error) {
	unknown := fail(CodeUnknownWorkload, "no device is mapped to this SPIFFE ID")
	if b.cfg.Devices == nil {
		return nil, unknown
	}
	dev, err := b.cfg.Devices.DeviceBySPIFFEID(ctx, spiffeID)
	if err != nil {
		if errors.Is(err, theauth.ErrStorageNotFound) {
			return nil, unknown
		}
		// A storage failure is not "unknown": fail closed but say why in the reason for logs.
		return nil, fail(CodePrincipalInactive, "device lookup failed")
	}
	if dev == nil {
		return nil, unknown
	}
	if !dev.Active() {
		// Same code as an unknown id (the TS bridge too), so a caller cannot tell a paused device from a missing one.
		return nil, fail(CodeUnknownWorkload, "the mapped device is not active")
	}
	return dev, nil
}

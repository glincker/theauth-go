package spiffe

import (
	"context"
	"errors"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go/v2"
)

type fakeDevices map[string]*theauth.Device

func (f fakeDevices) DeviceBySPIFFEID(_ context.Context, id string) (*theauth.Device, error) {
	if d, ok := f[id]; ok {
		return d, nil
	}
	return nil, theauth.ErrStorageNotFound
}

type brokenDevices struct{}

func (brokenDevices) DeviceBySPIFFEID(context.Context, string) (*theauth.Device, error) {
	return nil, errors.New("database down")
}

func vectorByName(t *testing.T, v vectorFile, name string) (chain []string, now time.Time) {
	t.Helper()
	for _, c := range v.X509 {
		if c.Name == name {
			return c.Chain, mustTime(t, c.Now)
		}
	}
	t.Fatalf("no vector %q", name)
	return nil, time.Time{}
}

func TestBridgeMapsX509AndJWTToDevice(t *testing.T) {
	v, _ := loadVectors(t)
	chain, now := vectorByName(t, v, "valid ec leaf")
	const id = "spiffe://example.org/ns/prod/sa/robot"
	devs := fakeDevices{id: {Name: "robot", SPIFFEID: id, Status: theauth.DeviceStatusActive}}
	var jwtNow time.Time
	br, err := New(Config{
		TrustDomains: map[string]TrustDomainConfig{"example.org": {Bundle: v.Bundle}},
		Audience:     []string{"https://theauth.example/api"},
		Devices:      devs,
		Now: func() time.Time {
			if !jwtNow.IsZero() {
				return jwtNow
			}
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, ferr := br.AuthenticatePEM(ctx, []byte(chain[0]))
	if ferr != nil {
		t.Fatalf("x509: %v", ferr)
	}
	if res.Device.Name != "robot" || res.Kind != "x509" || len(res.CNF["x5t#S256"]) != 43 {
		t.Fatalf("result: %+v", res)
	}
	// The JWT vector was signed at its own vector time, so the bridge clock moves there.
	var token string
	for _, c := range v.JWT {
		if c.Name == "valid ES256" {
			token, jwtNow = c.Token, mustTime(t, c.Now)
		}
	}
	res, ferr = br.AuthenticateJWT(ctx, token)
	if ferr != nil || res.Kind != "jwt" || res.CNF != nil {
		t.Fatalf("jwt: %v %+v", ferr, res)
	}

	// Suspended, unknown and a lookup that fails all refuse.
	devs[id].Status = theauth.DeviceStatusSuspended
	if _, ferr := br.AuthenticatePEM(ctx, []byte(chain[0])); ferr == nil || ferr.Code != CodeUnknownWorkload {
		t.Fatalf("suspended: %v", ferr)
	}
	delete(devs, id)
	if _, ferr := br.AuthenticatePEM(ctx, []byte(chain[0])); ferr == nil || ferr.Code != CodeUnknownWorkload {
		t.Fatalf("unmapped: %v", ferr)
	}
	broken, _ := New(Config{TrustDomains: map[string]TrustDomainConfig{"example.org": {Bundle: v.Bundle}}, Devices: brokenDevices{}, Now: func() time.Time { return now }})
	if _, ferr := broken.AuthenticatePEM(ctx, []byte(chain[0])); ferr == nil || ferr.Code != CodePrincipalInactive {
		t.Fatalf("broken lookup: %v", ferr)
	}
	if _, ferr := br.AuthenticatePEM(ctx, []byte("nothing")); ferr == nil || ferr.Code != CodeMalformed {
		t.Fatalf("no cert: %v", ferr)
	}
}

func TestBridgeRefusesBadConfig(t *testing.T) {
	if _, err := New(Config{TrustDomains: map[string]TrustDomainConfig{"example.org": {}}}); err == nil {
		t.Fatal("empty trust domain accepted")
	}
}

// Command device-client simulates a constrained device against a local stand in for the
// theAuth server: it signs an assertion, accepts a signed offline bundle, and decides
// offline. In production the bundle comes from `POST /devices/:id/bundle` on the TS core
// and the verification keys from `GET /device/jwks`; here a throwaway key plays the server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"os"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

const deviceID = "thermostat-7"

func main() {
	log := log.New(os.Stdout, "", 0)

	// Stand in for the server: a bundle signing key and one issued bundle.
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	server, err := device.NewSigner(serverPriv, nil)
	if err != nil {
		log.Fatal(err)
	}
	issued := time.Now()
	bundle, err := server.SignBundle("bundle-1", device.Claims{
		Issuer: device.DefaultIssuer, Subject: deviceID, Audience: deviceID,
		IssuedAt: issued.Unix(), NotBefore: issued.Unix(), Exp: issued.Add(time.Hour).Unix(),
		JTI: "example", Seq: issued.UnixMilli(), Owner: "owner-1", Groups: []string{"home"},
		Perms: []device.Permission{
			{Resource: "mqtt:sensors:temp:*", Actions: []string{"publish"}},
			{Resource: "coap:valve", Actions: []string{"put"}, Constraints: &device.Constraints{RequireApproval: true}},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	keys := device.NewKeySet(withKID(server.Public(), "bundle-1"))

	// The device: it has no RTC, so it anchors its clock to the bundle it just verified.
	boot := time.Now()
	clock := device.NewSyncedClock(func() time.Duration { return time.Since(boot) })
	clock.Sync(issued)

	now, ok := clock.Now()
	if !ok {
		log.Fatal("no time source, refusing")
	}
	var lastSeq int64 // persist this in flash between boots
	claims, err := device.VerifyBundle(bundle, device.VerifyOptions{Keys: keys, DeviceID: deviceID, LastSeq: lastSeq, Now: now})
	if err != nil {
		log.Fatal(err)
	}
	lastSeq = claims.Seq

	for _, q := range [][2]string{{"publish", "mqtt:sensors:temp:42"}, {"publish", "mqtt:actuators:fan"}, {"put", "coap:valve"}} {
		d := device.Evaluate(claims, q[0], q[1], device.WithNow(now))
		log.Printf("%s %s -> allowed=%v code=%s", q[0], q[1], d.Allowed, d.Code)
	}

	// Online: sign an assertion with the device's own key for Authorization: Bearer.
	_, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := device.NewSigner(devPriv, nil)
	if err != nil {
		log.Fatal(err)
	}
	token, err := signer.SignAssertion(deviceID, now, device.AssertionOptions{})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("assertion kid %s, %d bytes", signer.Public().KID, len(token))
}

func withKID(p device.PublicKey, kid string) device.PublicKey {
	p.KID = kid
	return p
}

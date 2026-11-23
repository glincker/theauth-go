// Command tinygocheck is the smoke test for building iot/device with TinyGo. It uses no log, fmt
// or os: only println, so the binary is as small as the library allows. It signs a bundle with a
// fixed test seed, verifies it, evaluates two requests, signs and verifies an assertion, and exits
// non zero on any surprise. Build and run it as described in docs/iot-device-client.md.
//
// The seed is public and for this check only. Never ship a key derived from a constant.
package main

import (
	"crypto/ed25519"
	"os"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

const deviceID = "thermostat-7"

func main() {
	if err := run(); err != nil {
		println("FAIL:", err.Error())
		os.Exit(1)
	}
	println("OK")
}

func run() error {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	server, err := device.NewSigner(ed25519.NewKeyFromSeed(seed), nil)
	if err != nil {
		return err
	}
	now := time.Unix(1_800_000_000, 0)
	bundle, err := server.SignBundle("bundle-1", device.Claims{
		Issuer: device.DefaultIssuer, Subject: deviceID, Audience: deviceID,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Exp: now.Add(time.Hour).Unix(),
		JTI: "check", Seq: now.UnixMilli(), Owner: "owner-1",
		Perms: []device.Permission{{Resource: "mqtt:sensors:temp:*", Actions: []string{"publish"}}},
	})
	if err != nil {
		return err
	}
	pub := server.Public()
	pub.KID = "bundle-1"
	claims, err := device.VerifyBundle(bundle, device.VerifyOptions{
		Keys: device.NewKeySet(pub), DeviceID: deviceID, Now: now,
	})
	if err != nil {
		return err
	}
	if d := device.Evaluate(claims, "publish", "mqtt:sensors:temp:42", device.WithNow(now)); !d.Allowed {
		return errString("allowed request was denied: " + string(d.Code))
	}
	if d := device.Evaluate(claims, "publish", "mqtt:actuators:fan", device.WithNow(now)); d.Allowed {
		return errString("unlisted resource was allowed")
	}
	token, err := server.SignAssertion(deviceID, now, device.AssertionOptions{})
	if err != nil {
		return err
	}
	if err := device.VerifyAssertion(token, server.Public(), deviceID, device.DefaultAudience, now); err != nil {
		return err
	}
	println("bundle bytes:", len(bundle), "assertion bytes:", len(token))
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

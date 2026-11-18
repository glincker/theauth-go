// Package revocationmqtt delivers the signed device revocation snapshot over MQTT as a retained
// message, and lets a device or gateway receive and verify it.
//
// A snapshot (iot/device RevocationSnapshot, typ device-revocations+jwt) is a compact JWS the
// server signs. It lists digests of the revoked and suspended device ids of one owner. Publishing it
// with the retain flag means a device that connects hours later still gets the newest one the moment
// it subscribes, with no HTTP round trip and no request to the server.
//
// The broker is only a courier. Trust comes from the signature: Receiver verifies every message with
// device.VerifyRevocations (signature, issuer, expiry, MaxAge, owner, sequence) and ignores the
// rest, so a compromised broker or a stray publisher can delay a snapshot but never forge one. Keep
// the publish permission on the topic to the server's own broker account, and give devices
// subscribe only. Topic ACLs for that are described in docs/mqtt-auth.md.
//
// The wire code is a small MQTT 3.1.1 client built on the standard library: CONNECT, retained
// PUBLISH at QoS 0 or 1, SUBSCRIBE at QoS 1. Mosquitto, EMQX and HiveMQ all speak it.
package revocationmqtt

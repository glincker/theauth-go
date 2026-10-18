// Package device is the device side of theAuth IoT identity: sign short lived device
// assertions, verify signed offline policy bundles, and decide offline with Evaluate.
//
// Formats follow the TS design (sdk/docs-local/design/iot-device-identity.md): D3 for the
// assertion, D7 for the bundle, D8 for resource names. Evaluate matches the TS
// evaluateDeviceBundle rule for rule, and testdata/vectors.json (generated from the TS
// code) is replayed by the tests.
//
// The package imports only the standard library, and none of encoding/json, reflect, fmt
// or os directly: a small JSON reader is built in, so the verify path suits TinyGo. See
// docs/iot-device-client.md.
package device

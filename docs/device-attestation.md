# Device hardware attestation

`iot/attest` checks hardware attestation evidence when a device enrolls: Android Key Attestation, Apple App Attest and TPM 2.0 quotes. It is a Go port of the TypeScript verifiers in `@glinr/theauth` (`sdk/packages/core/src/device/attestation`), uses only the Go standard library, and is tested against the same real vendor fixtures. Every shared vector gives the same decision, the same refusal text and the same claims as the TypeScript code.

A device that passes proves that a genuine piece of hardware holds a key and, depending on the verifier, which app or platform state it runs. It does not replace the join token or the proof of possession of [device-tokens.md](device-tokens.md). It adds a third check in front of them.

## How enrollment uses it

1. The device asks for a challenge (`POST /oauth/devices/challenge`). The response now has a `nonce` field, the `jti` of the challenge. The device already used that value as the `nonce` of its proof.
2. The device binds the same nonce into its hardware evidence: as the Android attestation challenge, as part of the App Attest client data, or as the TPM quote's qualifying data.
3. The device sends the evidence as `attestation_evidence` (a string holding the JSON document) next to `challenge` and `proof` in `POST /oauth/devices/enroll`.
4. The server checks the challenge and the proof first, then runs the verifier, then spends the join token. Refused evidence never costs a use of the token, and an attacker without the device key never reaches the verifier.

The verifier receives `Nonce` (the challenge nonce), `CredentialKind` (always `jwk`), `CredentialKeyThumbprint` (the RFC 7638 thumbprint of the enrolled key) and `EnrollmentID` (the join token id).

```go
package main

import (
	"log"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/iot/attest"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func main() {
	android, err := attest.NewAndroidKeyVerifier(attest.AndroidKeyOptions{
		Revocation:      attest.GoogleRevocationList(attest.GoogleRevocationListOptions{}),
		AllowedPackages: []string{"com.example.robot"},
	})
	if err != nil {
		log.Fatal(err)
	}
	_, err = theauth.New(theauth.Config{
		Storage: memory.New(),
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: "https://auth.example.com",
			DeviceTokens: &theauth.DeviceTokensConfig{
				Attestation: &theauth.DeviceAttestationConfig{Required: true, Verify: android},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

`DeviceAttestationConfig.Required` refuses enrollment without evidence. When it is false, a device may enroll without evidence, but evidence that is sent must pass. Evidence sent to a server with no `Attestation` config is refused, not ignored.

Refusals are `400`. A missing item answers `invalid_request` with the description `attestation_required`. A refused item answers `invalid_grant` with `attestation_failed: <reason>`, where the reason is the verifier's sentence (for example `Attestation challenge does not match the enrollment nonce`). A verifier that returns an error or panics answers plain `attestation_failed`, and the detail goes to the log and the audit event `device.enroll.attestation_refused`. In Go, `errors.Is(err, theauth.ErrDeviceAttestationRequired)` and `errors.Is(err, theauth.ErrDeviceAttestationFailed)` match, and `errors.As` with `*theauth.DeviceAttestationError` gives the reason.

On success the verified claims go into the `device.enrolled` audit event under `hardware_attestation` and are stored on the device as `Device.AttestationClaims` (a JSON column, migrations SQLite 0042, Postgres 0039, MySQL 0040). `Device.Attestation` still says how the device proved its identity (`join_token`). A device that enrolled without evidence has no claims.

Any function with the type `attest.Verifier` works, so you can write your own and combine them (try Android, then Apple) in one hook.

## The verifier contract

```go
type Verifier func(ctx context.Context, in attest.Input) (attest.Result, error)
```

A refusal is `Result{OK: false, Reason: "..."}` with a nil error. An error means the answer is unknown, for example the revocation list could not be fetched, and every caller treats it as a refusal. Constructors return an error for bad options and never build a verifier that would accept too much: an unknown enum value, an unparsable trust anchor, no revocation choice for Android, no roots for a TPM without `AllowUnverifiedAk`.

All three verifiers refuse an empty nonce. Option names match the TypeScript options (`AllowedPackages` for `allowedPackages`, and so on). Options whose default is true take a `*bool`, built with `attest.Bool(false)`.

## Android Key Attestation

```go
v, err := attest.NewAndroidKeyVerifier(attest.AndroidKeyOptions{
	Revocation:        attest.GoogleRevocationList(attest.GoogleRevocationListOptions{}),
	MinSecurityLevel:  attest.LevelStrongBox, // default attest.LevelTrustedEnvironment
	BootPolicy:        "verified",            // "verified_or_self_signed", or "any" for development devices
	AllowedPackages:   []string{"com.example.robot"},
	ChallengeEncoding: attest.ChallengeUTF8, // the nonce string as bytes, the default
})
```

It follows Google's published steps. The chain must end at a Google Hardware Attestation root. No certificate may be revoked. The key attestation extension must appear once, in the leaf (a copy higher up could have been added by an attacker). The attestation and the key must meet the minimum security level. The TEE enforced root of trust must show a locked bootloader and verified boot. The key must have been generated in hardware (`RequireGeneratedKey`, default true). The attestation challenge must equal the nonce. By default (`BindKey`) the attested key must be the enrolled key, so the enrolled credential is a `jwk` made from the attested EC P-256 or P-384 key.

Evidence is a JSON array of base64 DER certificates, leaf first, or `{"chain": [...]}`, one to eight entries.

- There is no default revocation choice. Pass `attest.GoogleRevocationList`, your own `RevocationCheck`, or set `RevocationDisabled` on purpose. The Google list is cached by its `Cache-Control` header, fails closed when it cannot be fetched, and tolerates an outage only for `StaleIfError`.
- The bundled roots are the two Google roots copied on 2026-10-18 (`attest.GoogleAttestationRoots`). Pass `Roots` to pin a newer list. Factory chains of the old root (subject serial `f92009e853b6b045`) are accepted after their `notAfter` date, as Google instructs, unless the chain carries the provisioning information extension.
- Not supported: chains that use an attest key to certify another key, the CBOR content of the provisioning information extension (only its position is checked), and matching `attestationIdSerial` or IMEI against a hardware id.

## Apple App Attest

```go
v, err := attest.NewAppleAppAttestVerifier(attest.AppleAppAttestOptions{
	AppIDs:      []string{"ABCDE12345.com.example.robot"}, // TeamID.BundleID, required
	Environment: attest.AppleProduction,                   // AppleDevelopment, or AppleAnyEnv
	Bind:        attest.BindClientData,                    // BindAttestedKey or BindNone
})
```

It follows Apple's Attestation Object Validation Guide: format `apple-appattest`, an `x5c` chain to the Apple App Attestation Root CA, a nonce equal to SHA-256 of `authData` followed by the client data hash, a key identifier equal to SHA-256 of the credential certificate's public key point and to the credential id, an `rpIdHash` equal to SHA-256 of an allowed App ID, counter 0, and the AAGUID of the expected environment.

With `BindClientData` (default) the app hashes `<nonce>:<RFC 7638 thumbprint of the enrolled key>` with SHA-256 and passes that as `clientDataHash` to `attestKey`, so Apple's certificate vouches for that exact pair. `BindAttestedKey` demands that the enrolled key is the App Attest key itself. `BindNone` checks the nonce only. Evidence is `{"attestation": "<base64>", "keyId": "<base64>"}`.

- The credential certificate lives about three days. Verify at enrollment. There is no revocation list for App Attest.
- `apple_validation_category_01` and `apple_bundle_version_01` from `authData` are returned as claims, and `AllowedValidationCategories` can require a category.
- The claims carry `attestedPublicKey` (the App Attest key as a base64 X9.62 point), which assertions are checked against. Assertions, receipts and the counter are below.
- Not built: asking Apple's service for a fresh fraud metric, and macOS specific checks.

## TPM 2.0 quotes

```go
v, err := attest.NewTPM2QuoteVerifier(attest.TPM2Options{
	Roots:             []string{vendorRootPEM},
	ChallengeEncoding: attest.ChallengeHex,
	ExpectedPCRs:      map[string]map[int]string{"sha256": {7: secureBootPCRHex}},
})
```

The attestation key must be a restricted signing key that cannot leave its TPM (`restricted`, `sign`, `fixedTPM`, `fixedParent`, not `decrypt`). The quote must be a `TPM_ST_ATTEST_QUOTE` with the `TPM_GENERATED` magic, its qualifying data must equal the nonce, its signature (RSASSA or ECDSA, SHA-256 or stronger) must verify under that key, its clock must be marked safe, and the PCR values in the evidence must hash to the signed digest. With `Roots`, the evidence must carry a certificate chain from the attestation key to a root you trust, and the leaf's public key must be the signing key.

Evidence is JSON: `akPublic` (TPMT_PUBLIC or TPM2B_PUBLIC, base64), `quote` (TPMS_ATTEST, base64), `signature` (TPMT_SIGNATURE, base64), `pcrs` (hex by bank and index, covering every PCR the quote selected) and `akCertificates` (base64 DER, leaf first).

- No bundled root: TPM vendors and clouds each run their own. Without `Roots` you must set `AllowUnverifiedAk`, and the claims say `akVerified: false`.
- The quote verifier does not run the credential activation handshake that proves an attestation key shares a TPM with an endorsement key, and it does not check `TPM2_Certify` of the enrolled key. A genuine TPM vouches for the nonce, but the quote does not prove the enrolled credential lives in that TPM. `NewTPM2CertifyVerifier` (below) does both. The event log, RSA-PSS and ECDAA are not supported.

## Apple App Attest assertions and receipts

An assertion proves a later request came from the app instance whose key was attested. `attest.VerifyAppleAssertion` follows the assertion steps of Apple's validation guide: it hashes the client data, computes `SHA-256(authenticatorData || clientDataHash)`, verifies the ECDSA signature over that with the attested key, checks `rpIdHash` against SHA-256 of your App ID and requires the counter to be higher than the stored one. `ReasonAssertionCounter` is the refusal text of a counter that did not grow.

For an enrolled device the service does it and keeps the counter:

```go
dev, err := auth.VerifyDeviceAppAssertion(ctx, deviceID, theauth.DeviceAppAssertionRequest{
	Assertion:  assertionBase64,
	ClientData: clientDataBytes, // put a server challenge in it and check the challenge yourself
})
var refused *theauth.DeviceAppAssertionError
if errors.As(err, &refused) {
	// refused.Code: device_not_found, device_blocked, not_app_attest, assertion_invalid, assertion_replayed
}
```

The key and App ID come from the stored claims (`attestedPublicKey`, `appId`). The counter is `Device.AppAttestCounter` and moves with `DeviceAppAttestStorage.AdvanceAppAttestCounter`, one conditional `UPDATE ... WHERE app_attest_counter < $new`, so racing requests with one assertion produce exactly one winner (the memory, SQLite, Postgres and MySQL stores implement it, and `storagetest.RunDeviceIdentity` has a 12 way race). A store without it makes `VerifyDeviceAppAssertion` refuse with `storage_unsupported`, because a counter that is not atomic gives no replay protection. Unlike the TypeScript module, Go keeps no nonce store for assertions, so the counter is the only replay protection kept here: embed a challenge in the client data and check it in your handler. Refusals write the audit event `device.app_assertion.refused`.

`attest.VerifyAppleReceipt` checks the fraud receipt Apple returns (a CMS object, with a small BER normalizer because Apple writes indefinite lengths): the signature, the chain (`Application Attestation Fraud Receipt Signing`, `Apple Application Integration CA 5 - G1`, `attest.AppleReceiptRoots` for Apple Root CA - G3), the App ID, optionally the attested key, and expiry. The result has the risk metric (keys seen in 30 days, only in a refreshed receipt), the times and the token for refreshing it. Refreshing is not done here.

Tested on the same real recordings as the TypeScript code (`testdata/apple-app-assertion.json`: veehaitch/devicecheck-appattest and block/buzz, both Apache License 2.0), 36 assertion and 39 receipt vectors generated from the TypeScript verifiers and replayed here with the same verdict, reason, counter and receipt fields, plus a real enrollment through the HTTP routes followed by the real assertion.

## TPM 2.0 credential activation and TPM2_Certify

`attest.NewTPM2CertifyVerifier` proves the attestation key (AK) and the endorsement key (EK) share one TPM, and that the enrolled key lives in that TPM and cannot be exported. The server half is TPM2_MakeCredential (`attest.MakeCredential`): it wraps a secret so that only the TPM holding the EK, with an AK of that name loaded, recovers it with TPM2_ActivateCredential. The device then sends the recovered secret with a TPM2_Certify of its key (signed by the AK, qualifying data the enrollment nonce) in the attestation evidence.

Flow with the HTTP routes:

1. `POST /oauth/devices/challenge` as usual, then `POST /oauth/devices/tpm-activation` with `join_token`, `jwk`, `challenge`, `proof`, `ek_public` and `ak_public` (TPMT_PUBLIC or TPM2B_PUBLIC, base64url). The answer is `credential_blob` and `encrypted_secret`. It spends nothing.
2. The device runs TPM2_ActivateCredential and TPM2_Certify.
3. `POST /oauth/devices/enroll` with `attestation_evidence` set to JSON with `ekPublic`, `akPublic`, `keyPublic`, `certifyInfo`, `signature`, `activation: {id, secret}` and, with `EKRoots`, `ekCertificates`.

The activation secret is derived, not stored: HMAC-SHA-256 of the enrollment nonce, the AK name and the EK name under a key derived from the authorization server's encryption key (`attest.DeriveActivationSecret`). The verifier gets that key in `attest.Input.ActivationKey` from enrollment and recomputes the secret, so no activation state exists, and a secret made for one enrollment, AK or EK is worthless for another. Compare with TypeScript, which stores a single use record for five minutes.

```go
v, err := attest.NewTPM2CertifyVerifier(attest.TPM2CertifyOptions{
	EKRoots: []string{manufacturerRootPEM}, // says the TPM is real; AllowUnverifiedEK for development
})
```

Without `EKRoots` nobody vouches that the EK belongs to a real TPM: the claims say `ekVerified: false` and the policy facts below read `software`.

Checked against a real TPM: swtpm 0.7.3 (a software TPM from libtpms) with tpm2-tools 5.7 and tpm2-pytss 2.3.0 in Docker made the EK, AK and key public areas for RSA and ECC and a real TPM2_Certify (`testdata/tpm2-swtpm.json`). The credential blobs from the TypeScript implementation, built with pinned randomness, were accepted by TPM2_ActivateCredential on that TPM for both key types, which recovered the secret. The Go implementation reproduces those blobs byte for byte (RSA seed and ECC ephemeral key pinned), and the Go verifier accepts the real Certify output. `docs-local/tpm2/run.sh` repeats the whole thing and prints whether the TPM recovered each secret; it needs Docker. An end to end enrollment test drives the routes with a simulated TPM. Not covered: hardware TPMs, real EK certificates, TPM 1.2.

## Policy on attestation claims

`theauth.DeviceAttestationFacts(device)` and `attest.FactsFromClaims` turn the stored claims into the facts policy reads (`device.AttestationFacts`): `SecurityLevel` (`software`, `hardware`, `strongbox`), `BootState` (Android only) and `AppIDs`. The mapping is the one in the TypeScript docs and replayed from 38 shared vectors: Android takes the lower of the attestation and key level (TEE is `hardware`), Apple App Attest is `hardware` (Secure Enclave), a TPM quote or certify is `hardware` only when its key or EK chained to a trusted root, and claims of an unknown format give no facts.

Put them in the signed offline bundle and the device decides permissions with an `attestation` constraint the way the TypeScript SDK does:

```go
facts, ok := theauth.DeviceAttestationFacts(dev)
claims := device.Claims{ /* ... */ Perms: []device.Permission{{
	Resource: "door:*", Actions: []string{"unlock"},
	Constraints: &device.Constraints{Attestation: device.NewAttestationConstraint(device.LevelHardware, []string{device.BootVerified}, nil)},
}}}
if ok {
	claims.Attestation = &facts
}
token, err := signer.SignBundle("kid", claims)
// on the device
decision := device.Evaluate(verified, "unlock", "door:front") // CodeAttestationRequired when the facts are weaker or missing
```

A bundle without facts denies every permission that has the constraint, as does a malformed rule or malformed facts. The check runs after rate limit and argument patterns and after the `requireApproval` short circuit, in the same order as the TypeScript bundle evaluation. 258 decision cases generated from `evaluateDeviceBundle` (every rule shape against every facts shape, ordering against the other constraints, malformed input) are replayed in `iot/device`. The Go authorization server itself mints scoped tokens, so there is no per action decision on the server side to extend: the offline bundle is where Go applies the constraint.

## Command line

`theauth-go device attest android|apple|tpm|tpm-certify|apple-assertion|apple-receipt` runs the same verifiers offline, with the same flags as `theauth device attest` plus `--activation-key` for `tpm-certify`. Exit code 0 when accepted, 1 when refused, 2 for a usage error. Accepted evidence also prints the policy facts. Run it with `--help` for the flags.

## Differences from the TypeScript verifiers

Same fixtures, same options, same refusal texts, same claims. These are deliberate:

- Constructors return an error where TypeScript throws, and a verifier returns `(Result, error)`. Only infrastructure failures (the revocation list) are errors.
- An empty nonce is refused up front by all three verifiers. TypeScript refuses only a missing nonce, and the TPM verifier refuses an empty one later with another sentence.
- `Revocation: "disabled"` is `RevocationDisabled: true`. `AllowedPackages` and `AllowedValidationCategories` apply when the slice is non nil, so an empty non nil slice refuses everything, like an empty array in TypeScript.
- A malformed extension inside a chain certificate is a refusal with the parser's text. In TypeScript that case throws out of the verifier, which the enrollment hook also treats as a refusal.
- The TPM verifier requires ECC point coordinates to be exactly the curve size and an RSA modulus that really has 2048 bits (TypeScript trusts the declared size). `ExpectedPCRs` with an unknown bank name fails at construction.
- Enrollment hook: the nonce is the challenge `jti` (no separate nonce endpoint, no nonce store), the credential is always `jwk`, and no hardware id is passed. Claims are stored on the device record and also written to the audit log.
- The TPM activation secret is derived with an HMAC instead of stored, and App Attest assertions have no nonce store (see above).

## How this was tested

`iot/attest/testdata` holds the real vendor fixtures from the TypeScript repo, copied unmodified, with their license notes in `testdata/README.md`: Google's Android Key Attestation chains (TEE and StrongBox, EC and RSA), three Apple App Attest objects (Apple's guide sample and two device recordings), and Google Compute Engine vTPM quotes. `testdata/vectors.json` has 131 cases generated by running the TypeScript verifiers over those fixtures and over tampered copies (`testdata/gen-vectors.mts`). The Go test replays every case and compares the decision, the reason and the claims. Negative cases include Google's EC StrongBox chain, which is not a valid chain (its leaf signature matches neither certificate above it) and is refused in both languages with the same sentence, and every tampering, wrong nonce, wrong root and expired chain case. Parsers also have fuzz targets.

The same limits apply as in TypeScript. There is no chain from a locked, verified Android device with a known private key, no App Attest object produced with this project's client data format, and one vendor of virtual TPM. Treat the verifiers as reviewed against the vendor documents and tested against real fixtures, not as certified by Google, Apple or the TCG.

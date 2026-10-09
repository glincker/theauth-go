# Passkey attestation policy and AAGUID rules

By default theauth-go asks authenticators for no attestation, which is what
you want for a consumer app: any passkey provider works and nothing about the
device model is learned. If you run an enterprise or regulated deployment you
can opt in to attestation and restrict which authenticator models may register.

All of this is configuration on `WebAuthnConfig`. Leaving the new fields empty
keeps the old behavior.

## Fields

| Field | Meaning |
| --- | --- |
| `AttestationPreference` | `none` (default), `indirect`, `direct` or `enterprise`. Sent to the browser as the attestation conveyance. |
| `RequireAttestationStatement` | Reject registrations whose attestation format is `none`. Use together with `direct`. |
| `AAGUIDAllowlist` | When non-empty, only these authenticator models can register. |
| `AAGUIDDenylist` | These models are always rejected. It wins over the allowlist. |
| `AuthenticatorNames` | Map of AAGUID to display name, for showing "YubiKey 5" instead of a UUID. |
| `AuthenticatorName` | Optional lookup function, consulted before `AuthenticatorNames`. |

AAGUIDs are UUID strings. Dashes and letter case do not matter. An invalid
value makes `theauth.New` return an error, so typos fail at startup.

## Example

```go
a, err := theauth.New(theauth.Config{
    // Storage, BaseURL, EncryptionKey ...
    WebAuthn: &theauth.WebAuthnConfig{
        RPID:      "example.com",
        RPOrigins: []string{"https://example.com"},

        AttestationPreference:       "direct",
        RequireAttestationStatement: true,
        AAGUIDAllowlist: []string{
            "2fc0579f-8113-47ea-b116-bb5a8db9202a", // YubiKey 5 NFC
        },
        AuthenticatorNames: map[string]string{
            "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 NFC",
        },
    },
})
```

To show a name next to a stored passkey:

```go
label := a.PasskeyAuthenticatorName(cred.AAGUID) // "" when unknown
```

The AAGUID of every registered credential is already stored on the credential
row, so no migration is needed.

## What is and is not verified

The upstream go-webauthn library checks the attestation statement formats it
supports (packed, fido-u2f, tpm, android-key and so on) when the authenticator
sends one. theauth-go does not load the FIDO Metadata Service, so certificate
chains are not validated against vendor trust anchors. The AAGUID lists are the
policy control: they decide which models you accept, but an AAGUID is
self-reported unless the attestation statement is verified. Treat the
allowlist as strong only when `RequireAttestationStatement` is on.

Many platform passkey providers return no attestation even when asked for
`direct`. With `RequireAttestationStatement` they cannot register, which is
usually the point of an allowlist deployment and a poor fit for consumer apps.

## RP ID and origins

`RPID` is fixed by configuration and never derived from the request host. Every
origin that may complete a ceremony must be listed in `RPOrigins`, including a
separate front end host or a Safari-specific domain. A ceremony from an origin
that is not listed fails, and the RP ID returned to the browser is always the
configured one.

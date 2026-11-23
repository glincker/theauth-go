package attest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"
)

// nonceOID is the credential certificate extension that carries the nonce (Apple's validation
// guide, step 4).
const nonceOID = "1.2.840.113635.100.8.2"

var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
)

// Apple App Attest environments for AppleAppAttestOptions.Environment.
const (
	AppleProduction  = "production"
	AppleDevelopment = "development"
	AppleAnyEnv      = "any"
)

// App Attest binding modes for AppleAppAttestOptions.Bind.
const (
	BindClientData  = "client-data"
	BindAttestedKey = "attested-key"
	BindNone        = "none"
)

// Client data hash modes for AppleAppAttestOptions.ClientDataHash.
const (
	HashSHA256 = "sha256"
	HashRaw    = "raw"
)

// AppleAppAttestOptions are the options of NewAppleAppAttestVerifier. Names follow the
// TypeScript AppleAppAttestOptions.
type AppleAppAttestOptions struct {
	// AppIDs are the accepted App IDs, each "<TeamID>.<BundleID>". Required: the attestation
	// proves a key lives in some app on a genuine Apple device, and the App ID hash is how you
	// know it is yours. An empty list refuses everything.
	AppIDs []string
	// Roots are trust anchors as PEM or base64 DER. Default: AppleAppAttestRoots.
	Roots []string
	// Environment is AppleProduction (default), AppleDevelopment or AppleAnyEnv.
	Environment string
	// Bind says how the attestation is tied to the credential the device enrolls (credential
	// kind jwk, RFC 7638 thumbprint). BindClientData (default): the app hashes
	// "<nonce>:<thumbprint>" as its client data. BindAttestedKey: the enrolled key must be the App
	// Attest key itself. BindNone: nonce only.
	Bind string
	// ClientDataHash is how the app derived clientDataHash from the client data. HashSHA256
	// (default) is SHA-256 of the client data bytes, HashRaw means the app passed them as is.
	ClientDataHash string
	// ChallengeEncoding is how the nonce string maps to bytes. Default ChallengeUTF8.
	ChallengeEncoding ChallengeEncoding
	// AllowedValidationCategories, when non nil, requires the apple_validation_category_01
	// extension to be present and one of these values.
	AllowedValidationCategories []int64
	// Now is the clock for validity checks. Tests inject one.
	Now func() time.Time
}

// ParseAppleAppAttestEvidence reads App Attest evidence, JSON of the form
// {"attestation": "<base64 attestation object>", "keyId": "<base64 key identifier>"}.
func ParseAppleAppAttestEvidence(evidence string) (attestation, keyID []byte, err error) {
	var parsed any
	if json.Unmarshal([]byte(evidence), &parsed) != nil {
		return nil, nil, reasonErr("Evidence is not JSON")
	}
	obj, _ := parsed.(map[string]any)
	a, aok := obj["attestation"].(string)
	k, kok := obj["keyId"].(string)
	if !aok || !kok || utf16Len(a) < 1 || utf16Len(a) > 65536 || utf16Len(k) < 1 || utf16Len(k) > 128 {
		return nil, nil, reasonErr("Evidence needs string fields attestation and keyId")
	}
	if attestation, err = decodeBase64(a); err == nil {
		keyID, err = decodeBase64(k)
	}
	if err != nil {
		return nil, nil, reasonErr("Evidence fields are not base64")
	}
	return attestation, keyID, nil
}

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

type authData struct {
	rpIDHash     []byte
	counter      uint32
	aaguid       []byte
	credentialID []byte
	hasCOSE      bool
	coseX, coseY []byte
	extensions   cborMap
}

// parseAuthData reads authenticator data as WebAuthn defines it (rpIdHash, flags, counter,
// attested credential data, optional extensions).
func parseAuthData(auth []byte) (*authData, error) {
	if len(auth) < 55 {
		return nil, errors.New("authData is too short")
	}
	flags := auth[32]
	if flags&0x40 == 0 {
		return nil, errors.New("authData has no attested credential data")
	}
	credEnd := 55 + int(binary.BigEndian.Uint16(auth[53:55]))
	if credEnd > len(auth) {
		return nil, errors.New("credentialId runs past authData")
	}
	value, size, err := decodeCBORPrefix(auth[credEnd:])
	if err != nil {
		return nil, err
	}
	rest := auth[credEnd+size:]
	extensions := cborMap{}
	// WebAuthn says the ED flag (0x80) announces extensions. Apple's own 2026 sample carries an
	// extension map with flags 0x40, so the flag is not trusted either way: bytes after the key
	// must be exactly one map, and the ED flag may not promise a map that is missing.
	if len(rest) > 0 {
		ext, esize, err := decodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		m, ok := ext.(cborMap)
		if !ok {
			return nil, errors.New("authData extensions are not a map")
		}
		extensions = m
		rest = rest[esize:]
	} else if flags&0x80 != 0 {
		return nil, errors.New("authData promises extensions but has none")
	}
	if len(rest) != 0 {
		return nil, errors.New("authData has trailing bytes")
	}
	out := &authData{
		rpIDHash: auth[:32], counter: binary.BigEndian.Uint32(auth[33:37]), aaguid: auth[37:53],
		credentialID: auth[55:credEnd], extensions: extensions,
	}
	if cose, ok := value.(cborMap); ok {
		xv, _ := cose.num(-2)
		yv, _ := cose.num(-3)
		x, xok := xv.([]byte)
		y, yok := yv.([]byte)
		if xok && yok {
			out.hasCOSE, out.coseX, out.coseY = true, x, y
		}
	}
	return out, nil
}

// nonceFromExtension returns the single OCTET STRING inside the nonce extension:
// SEQUENCE { [1] { OCTET STRING } } as Apple issues it, or SEQUENCE { OCTET STRING }.
func nonceFromExtension(value []byte) ([]byte, bool) {
	top, err := parseOne(value)
	if err != nil {
		return nil, false
	}
	seq, err := children(top)
	if err != nil || len(seq) != 1 {
		return nil, false
	}
	inner := seq[0]
	if inner.cls == 2 && inner.constructed {
		kids, err := children(inner)
		if err != nil || len(kids) != 1 {
			return nil, false
		}
		inner = kids[0]
	}
	if !isUniversal(inner, tagOctetString) {
		return nil, false
	}
	return inner.content, true
}

// p256Point returns the uncompressed X9.62 point (0x04 || X || Y) of a P-256 SubjectPublicKeyInfo.
func p256Point(spki []byte) []byte {
	info, err := spkiInfo(spki)
	if err != nil || info.alg != oidECPublicKey || info.curve != oidCurveP256 {
		return nil
	}
	top, err := parseOne(spki)
	if err != nil {
		return nil
	}
	kids, err := children(top)
	if err != nil || len(kids) < 2 {
		return nil
	}
	point, err := bitStringBytes(kids[1])
	if err != nil || len(point) != 65 || point[0] != 4 {
		return nil
	}
	return point
}

// numberExtension reads an integer authData extension. Apple's 2026 sample stores the category
// as four little endian bytes.
func numberExtension(v any, ok bool) (int64, bool) {
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case []byte:
		if len(n) == 4 {
			return int64(binary.LittleEndian.Uint32(n)), true
		}
	}
	return 0, false
}

// NewAppleAppAttestVerifier returns a verifier for Apple App Attest attestation objects.
//
// It follows Apple's "Validating apps that connect to your server" and "Attestation Object
// Validation Guide" step by step: format apple-appattest, an x5c chain of the credential and
// intermediate certificates to the Apple App Attestation Root CA, a nonce equal to SHA-256 of
// authData followed by the client data hash (checked against the credential certificate's
// 1.2.840.113635.100.8.2 extension), a key identifier equal to SHA-256 of the certificate's
// public key point and to the credential id, rpIdHash equal to SHA-256 of the App ID, counter
// zero, and the AAGUID of the expected environment. Sources:
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server and
// https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
func NewAppleAppAttestVerifier(opts AppleAppAttestOptions) (Verifier, error) {
	if !opts.ChallengeEncoding.valid() {
		return nil, fmt.Errorf("attest: unknown ChallengeEncoding %q", opts.ChallengeEncoding)
	}
	environment := opts.Environment
	if environment == "" {
		environment = AppleProduction
	}
	if environment != AppleProduction && environment != AppleDevelopment && environment != AppleAnyEnv {
		return nil, fmt.Errorf("attest: unknown Environment %q", opts.Environment)
	}
	bind := opts.Bind
	if bind == "" {
		bind = BindClientData
	}
	if bind != BindClientData && bind != BindAttestedKey && bind != BindNone {
		return nil, fmt.Errorf("attest: unknown Bind %q", opts.Bind)
	}
	hashMode := opts.ClientDataHash
	if hashMode == "" {
		hashMode = HashSHA256
	}
	if hashMode != HashSHA256 && hashMode != HashRaw {
		return nil, fmt.Errorf("attest: unknown ClientDataHash %q", opts.ClientDataHash)
	}
	roots := opts.Roots
	if roots == nil {
		roots = AppleAppAttestRoots
	}
	anchors, err := parseAnchors(roots)
	if err != nil {
		return nil, fmt.Errorf("attest: trust anchor: %w", err)
	}

	return func(_ context.Context, in Input) (Result, error) {
		if in.Nonce == "" {
			return fail("App Attest needs the enrollment nonce")
		}
		if len(opts.AppIDs) == 0 {
			return fail("No App ID is allowed")
		}
		if bind != BindNone && (in.CredentialKind != "jwk" || in.CredentialKeyThumbprint == "") {
			return fail("Enroll a jwk credential: the attestation must be bound to the enrolled key")
		}
		attestation, keyID, err := ParseAppleAppAttestEvidence(in.Evidence)
		if err != nil {
			return fail(err.Error())
		}

		obj, err := decodeCBORExact(attestation)
		if err != nil {
			return fail(err.Error())
		}
		m, ok := obj.(cborMap)
		if !ok {
			return fail("Attestation object is not a map")
		}
		fmtV, _ := m.str("fmt")
		adV, _ := m.str("authData")
		authBytes, hasAuth := adV.([]byte)
		stmtV, _ := m.str("attStmt")
		var x5c any
		if stmt, ok := stmtV.(cborMap); ok {
			x5c, _ = stmt.str("x5c")
		}
		if fmtV != "apple-appattest" {
			return fail("Attestation format is not apple-appattest")
		}
		if !hasAuth {
			return fail("Attestation object has no authData")
		}
		certs, ok := x5c.([]any)
		if !ok || len(certs) != 2 {
			return fail("x5c must hold the credential and the intermediate certificate")
		}
		chain := make([]*certificate, 0, 2)
		for _, c := range certs {
			der, ok := c.([]byte)
			if !ok {
				return fail("x5c entry is not a byte string")
			}
			cert, err := parseCertificate(der)
			if err != nil {
				return fail(err.Error())
			}
			chain = append(chain, cert)
		}
		auth, err := parseAuthData(authBytes)
		if err != nil {
			return fail(err.Error())
		}
		cred := chain[0]

		result, err := verifyChain(chain, anchors, chainOptions{now: clock(opts.Now)})
		if err != nil {
			return fail(err.Error())
		}
		if !result.ok {
			return fail(result.reason)
		}

		// Steps 3 and 4: nonce = SHA-256(authData || clientDataHash), compared with the certificate extension.
		nonceBytes, err := opts.ChallengeEncoding.encode(in.Nonce)
		if err != nil {
			return fail("Nonce cannot be encoded as the client data")
		}
		clientData := nonceBytes
		if bind == BindClientData {
			clientData = concat(nonceBytes, []byte(":"+in.CredentialKeyThumbprint))
		}
		clientDataHash := clientData
		if hashMode == HashSHA256 {
			clientDataHash = sha256Sum(clientData)
		}
		expectedNonce := sha256Sum(concat(authBytes, clientDataHash))
		var certNonce []byte
		var hasNonce bool
		if ext, ok := cred.extensions[nonceOID]; ok {
			certNonce, hasNonce = nonceFromExtension(ext.value)
		}
		if !hasNonce || !constantTimeEqual(certNonce, expectedNonce) {
			return fail("Attestation nonce does not match the enrollment nonce")
		}

		// Steps 5 and 8: key identifier is SHA-256 of the X9.62 point, and equals the credential id.
		point := p256Point(cred.spki)
		if point == nil {
			return fail("Credential certificate key is not an EC P-256 key")
		}
		if !constantTimeEqual(sha256Sum(point), keyID) {
			return fail("Key id is not the hash of the attested key")
		}
		if !constantTimeEqual(auth.credentialID, keyID) {
			return fail("credentialId is not the key id")
		}
		if auth.hasCOSE && !constantTimeEqual(concat(auth.coseX, auth.coseY), point[1:]) {
			return fail("authData key differs from the credential certificate key")
		}

		// Step 6: rpIdHash is SHA-256 of the App ID.
		appID := ""
		for _, candidate := range opts.AppIDs {
			if constantTimeEqual(sha256Sum([]byte(candidate)), auth.rpIDHash) {
				appID = candidate
			}
		}
		if appID == "" {
			return fail("Attested app is not an allowed App ID")
		}

		// Step 7: counter zero, and the AAGUID of the environment we expect.
		if auth.counter != 0 {
			return fail("Attestation counter is not zero")
		}
		isProd := constantTimeEqual(auth.aaguid, aaguidProduction)
		isDev := constantTimeEqual(auth.aaguid, aaguidDevelopment)
		if (!isProd && !isDev) || (isProd && environment == AppleDevelopment) || (isDev && environment == AppleProduction) {
			return fail("Attestation environment is not accepted")
		}

		catRaw, catPresent := auth.extensions.str("apple_validation_category_01")
		category, hasCategory := numberExtension(catRaw, catPresent)
		if opts.AllowedValidationCategories != nil {
			allowed := false
			for _, c := range opts.AllowedValidationCategories {
				if hasCategory && c == category {
					allowed = true
				}
			}
			if !allowed {
				return fail("Validation category is not accepted")
			}
		}
		bundleVersion, _ := auth.extensions.str("apple_bundle_version_01")

		attestedKey := keyThumbprint(cred.spki)
		if bind == BindAttestedKey && (attestedKey == "" || attestedKey != in.CredentialKeyThumbprint) {
			return fail("Attested key is not the enrolled key")
		}

		env := "development"
		if isProd {
			env = "production"
		}
		claims := map[string]any{
			"format":      "apple-app-attest",
			"bound":       bind,
			"environment": env,
			"appId":       appID,
			"keyId":       base64.StdEncoding.EncodeToString(keyID),
			// The attested key as an X9.62 point, so assertions can be verified later (VerifyAppleAssertion).
			"attestedPublicKey":     base64.StdEncoding.EncodeToString(point),
			"attestationRootSerial": result.anchor.serialHex,
		}
		if attestedKey != "" {
			claims["attestedKeyThumbprint"] = attestedKey
		}
		if hasCategory {
			claims["validationCategory"] = category
		}
		if s, ok := bundleVersion.(string); ok {
			claims["bundleVersion"] = s
		}
		return Result{OK: true, Claims: claims}, nil
	}, nil
}

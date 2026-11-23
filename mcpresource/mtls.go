package mcpresource

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// mtls.go: RFC 8705 section 3 certificate bound access tokens. A token whose
// cnf claim carries x5t#S256 is only accepted on a request that presents the
// client certificate with that SHA-256 thumbprint. The check runs in
// addition to the DPoP check: a token bound to both members needs a DPoP
// proof and the certificate (RFC 7800 allows several confirmation members,
// and accepting one while ignoring the other would weaken the binding).

var (
	errMTLSNoCert   = errors.New("mcpresource: certificate bound token needs a client certificate")
	errMTLSMismatch = errors.New("mcpresource: client certificate does not match cnf x5t#S256")
)

// CertThumbprint returns the RFC 8705 x5t#S256 value for cert: the base64url
// encoding, without padding, of the SHA-256 digest of the DER certificate.
func CertThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// WithClientCertThumbprint tells the validator how to read the thumbprint of
// the client certificate for a request, for deployments where TLS ends at a
// proxy. fn returns the base64url SHA-256 thumbprint of the certificate the
// proxy verified, or "" when there is none. Only trust a header that your
// proxy sets itself and strips from inbound traffic.
//
// Without this option the validator reads the leaf certificate of the TLS
// connection (r.TLS.PeerCertificates). A token with x5t#S256 and no
// certificate is always refused.
func WithClientCertThumbprint(fn func(*http.Request) string) Option {
	return func(v *Validator) { v.clientCertThumbprint = fn }
}

// bindMTLS enforces the x5t#S256 member and returns the matched thumbprint.
func (v *Validator) bindMTLS(r *http.Request, want string) (string, error) {
	got := ""
	switch {
	case v.clientCertThumbprint != nil:
		got = v.clientCertThumbprint(r)
	case r.TLS != nil && len(r.TLS.PeerCertificates) > 0:
		got = CertThumbprint(r.TLS.PeerCertificates[0])
	}
	if got == "" {
		return "", errMTLSNoCert
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return "", errMTLSMismatch
	}
	return got, nil
}

// bindConfirmation enforces every member of cnf the validator understands and
// records the result on principal. A cnf with neither jkt nor x5t#S256 leaves
// the token as a plain bearer token.
func (v *Validator) bindConfirmation(r *http.Request, token, scheme string, cnf *confirmationClaim, principal *Principal, now time.Time) error {
	if cnf == nil {
		return nil
	}
	if cnf.JKT != "" {
		jkt, err := v.bindDPoP(r, token, scheme, cnf.JKT, now)
		if err != nil {
			return err
		}
		principal.CnfJKT = jkt
	}
	if cnf.X5tS256 != "" {
		x5t, err := v.bindMTLS(r, cnf.X5tS256)
		if err != nil {
			return err
		}
		principal.CnfX5tS256 = x5t
	}
	return nil
}

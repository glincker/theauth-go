package theauth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// samlServiceProviderFor builds a per-connection crewjam/saml ServiceProvider
// using the global SP keypair (cfg.SAML) and the connection-specific IdP
// metadata stored on the SAMLConnection row. We do not cache the SP across
// calls; building one is cheap (a few struct copies and an IdP cert parse)
// and rebuilding on every login keeps the IdP cert rotation flow simple
// (rotate the cert in the saml_connections row; the next login sees it).
func (a *TheAuth) samlServiceProviderFor(conn *SAMLConnection) (*saml.ServiceProvider, error) {
	if a.samlCfg == nil || a.samlSPCert == nil || a.samlSPKey == nil {
		return nil, errors.New("theauth: SAML not configured")
	}
	idpCert, err := parseIdPCert(conn.IdPX509Cert)
	if err != nil {
		return nil, fmt.Errorf("theauth: idp cert: %w", err)
	}
	ssoURL, err := url.Parse(conn.IdPSSOURL)
	if err != nil {
		return nil, fmt.Errorf("theauth: idp sso url: %w", err)
	}
	acsURL, err := url.Parse(conn.SPACSURL)
	if err != nil {
		return nil, fmt.Errorf("theauth: sp acs url: %w", err)
	}
	mdURL := *acsURL
	mdURL.Path = mdURL.Path + "/metadata"
	idpMD := &saml.EntityDescriptor{
		EntityID: conn.IdPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: idpCertBase64(idpCert)},
										},
									},
								},
							},
						},
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: ssoURL.String(),
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: ssoURL.String(),
					},
				},
			},
		},
	}
	sp := &saml.ServiceProvider{
		EntityID:          conn.SPEntityID,
		Key:               a.samlSPKey,
		Certificate:       a.samlSPCert,
		MetadataURL:       mdURL,
		AcsURL:            *acsURL,
		IDPMetadata:       idpMD,
		AllowIDPInitiated: true,
	}
	return sp, nil
}

// parseIdPCert parses a PEM-encoded X.509 certificate. Accepts CRLF and LF
// line endings; trims surrounding whitespace.
func parseIdPCert(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// idpCertBase64 returns the base64-encoded DER bytes (no PEM headers) that
// crewjam/saml expects in X509Certificate.Data.
func idpCertBase64(c *x509.Certificate) string {
	return base64StdEnc(c.Raw)
}

// samlAuthnGCLoop drops AuthnRequest IDs whose TTL has expired. Runs every
// minute; a missed sweep is harmless because the SP's ParseResponse also
// enforces the request-ID match.
func (a *TheAuth) samlAuthnGCLoop() {
	if a.samlCfg == nil {
		return
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-a.samlAuthnStop:
			return
		case now := <-tick.C:
			a.samlAuthnInFlight.Range(func(k, v interface{}) bool {
				deadline, ok := v.(time.Time)
				if !ok || now.After(deadline) {
					a.samlAuthnInFlight.Delete(k)
				}
				return true
			})
		}
	}
}

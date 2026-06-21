// Package samltest provides an in-process SAML IdP for end-to-end testing
// of the SP integration. It generates a fresh RSA keypair on first use,
// signs assertions with it, and exposes the matching PEM-encoded cert so a
// SAMLConnection row can pin to it.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	once        sync.Once
	idpKey      *rsa.PrivateKey
	idpCert     *x509.Certificate
	idpCertPEM  string
	idpEntityID = "http://idp.samltest.local/metadata"
	idpSSOURL   = "http://idp.samltest.local/sso"
)

func ensure() {
	once.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Errorf("samltest: rsa keygen: %w", err))
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "samltest-idp"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			panic(fmt.Errorf("samltest: cert: %w", err))
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			panic(fmt.Errorf("samltest: parse cert: %w", err))
		}
		idpKey = k
		idpCert = c
		idpCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	})
}

// IdPEntityID returns a stable entity URL for the in-process IdP.
func IdPEntityID() string {
	ensure()
	return idpEntityID
}

// IdPSSOURL returns a stable SSO endpoint URL for the in-process IdP.
func IdPSSOURL() string {
	ensure()
	return idpSSOURL
}

// IdPCertPEM returns the PEM-encoded signing cert.
func IdPCertPEM() string {
	ensure()
	return idpCertPEM
}

// Assertion is the minimal SAML assertion payload the in-process IdP
// produces. Used by both the happy-path and the "missing email" branch
// tests; mutate the fields before calling Sign or Tamper.
type Assertion struct {
	AudienceURI  string
	RecipientURL string
	Issuer       string
	NameID       string
	NameIDFormat string
	Email        string
	GivenName    string
	FamilyName   string
	DisplayName  string
	Groups       []string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	InResponseTo string
	// SkipSign, when true, returns an unsigned assertion (used by the
	// "rejects unsigned" test case).
	SkipSign bool
}

// Default returns an assertion pre-filled with sensible defaults for one
// of the standard test cases. The caller overrides only what it cares
// about before calling SignAndEncode.
func Default(audience, recipient string) Assertion {
	now := time.Now()
	return Assertion{
		AudienceURI:  audience,
		RecipientURL: recipient,
		Issuer:       IdPEntityID(),
		NameID:       "user-1@samltest.local",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Email:        "user-1@samltest.local",
		GivenName:    "Test",
		FamilyName:   "User",
		DisplayName:  "Test User",
		NotBefore:    now.Add(-time.Minute),
		NotOnOrAfter: now.Add(10 * time.Minute),
	}
}

// SignAndEncode returns the base64-encoded XML SAML Response containing
// the assertion, signed by the in-process IdP. Suitable for direct use as
// the SAMLResponse form value on the ACS endpoint.
func (a Assertion) SignAndEncode() (string, error) {
	ensure()
	now := time.Now()
	resp := buildResponse(a, now)

	signed := resp
	if !a.SkipSign {
		signedDoc, err := signAssertion(resp)
		if err != nil {
			return "", err
		}
		signed = signedDoc
	}

	xmlBytes, err := signed.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(xmlBytes), nil
}

// buildResponse constructs a minimal but standards-compliant Response
// document holding one Assertion.
func buildResponse(a Assertion, issueInstant time.Time) *etree.Document {
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_resp_"+randID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", issueInstant.UTC().Format(time.RFC3339))
	resp.CreateAttr("Destination", a.RecipientURL)
	if a.InResponseTo != "" {
		resp.CreateAttr("InResponseTo", a.InResponseTo)
	}

	issuer := resp.CreateElement("saml:Issuer")
	issuer.SetText(a.Issuer)

	status := resp.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	// Assertion. We add the signed Signature inline so dsig validates
	// against the assertion (not the response).
	assertionID := "_assert_" + randID()
	assertion := resp.CreateElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", issueInstant.UTC().Format(time.RFC3339))

	issuer2 := assertion.CreateElement("saml:Issuer")
	issuer2.SetText(a.Issuer)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", a.NameIDFormat)
	nameID.SetText(a.NameID)

	confirmation := subject.CreateElement("saml:SubjectConfirmation")
	confirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	confirmationData := confirmation.CreateElement("saml:SubjectConfirmationData")
	confirmationData.CreateAttr("NotOnOrAfter", a.NotOnOrAfter.UTC().Format(time.RFC3339))
	confirmationData.CreateAttr("Recipient", a.RecipientURL)
	if a.InResponseTo != "" {
		confirmationData.CreateAttr("InResponseTo", a.InResponseTo)
	}

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", a.NotBefore.UTC().Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", a.NotOnOrAfter.UTC().Format(time.RFC3339))
	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(a.AudienceURI)

	authnStmt := assertion.CreateElement("saml:AuthnStatement")
	authnStmt.CreateAttr("AuthnInstant", issueInstant.UTC().Format(time.RFC3339))
	authnStmt.CreateAttr("SessionIndex", "session-"+randID())
	authnCtx := authnStmt.CreateElement("saml:AuthnContext")
	authnCtxRef := authnCtx.CreateElement("saml:AuthnContextClassRef")
	authnCtxRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	if a.Email != "" || a.GivenName != "" || a.FamilyName != "" || a.DisplayName != "" || len(a.Groups) > 0 {
		stmt := assertion.CreateElement("saml:AttributeStatement")
		addAttr := func(name, value string) {
			if value == "" {
				return
			}
			attr := stmt.CreateElement("saml:Attribute")
			attr.CreateAttr("Name", name)
			val := attr.CreateElement("saml:AttributeValue")
			val.SetText(value)
		}
		addAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", a.Email)
		addAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", a.GivenName)
		addAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", a.FamilyName)
		addAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", a.DisplayName)
		if len(a.Groups) > 0 {
			groupsAttr := stmt.CreateElement("saml:Attribute")
			groupsAttr.CreateAttr("Name", "http://schemas.xmlsoap.org/claims/Group")
			for _, g := range a.Groups {
				val := groupsAttr.CreateElement("saml:AttributeValue")
				val.SetText(g)
			}
		}
	}

	return doc
}

// signAssertion signs the (single) Assertion element inside the Response
// using the in-process IdP's RSA key.
func signAssertion(doc *etree.Document) (*etree.Document, error) {
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("samltest: empty document")
	}
	assertion := root.FindElement("//Assertion")
	if assertion == nil {
		return nil, fmt.Errorf("samltest: no assertion element")
	}

	ctx := dsig.NewDefaultSigningContext(&keystore{})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	signed, err := ctx.SignEnveloped(assertion)
	if err != nil {
		return nil, err
	}
	// Replace the assertion in place.
	parent := assertion.Parent()
	for i, child := range parent.ChildElements() {
		if child == assertion {
			parent.RemoveChildAt(i)
			parent.InsertChildAt(i, signed)
			break
		}
	}
	return doc, nil
}

// keystore implements goxmldsig's X509KeyStore using the in-process IdP key.
type keystore struct{}

func (keystore) GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error) {
	ensure()
	return idpKey, idpCert.Raw, nil
}

// randID returns a short hex-encoded random identifier suitable for an XML ID.
func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

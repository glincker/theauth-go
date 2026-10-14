package sqlite_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beevik/etree"
	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/go-chi/chi/v5"
	dsig "github.com/russellhaering/goxmldsig"
)

// testIdP is a minimal in-process SAML IdP: one RSA key and a signer for a
// bearer assertion. internal/samltest is not importable from this module.
type testIdP struct {
	key     *rsa.PrivateKey
	certDER []byte
	certPEM string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sqlite-e2e-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdP{key: k, certDER: der, certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (p *testIdP) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return p.key, p.certDER, nil }

const (
	idpEntity = "http://idp.e2e.local/metadata"
	nsSAMLP   = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSAML    = "urn:oasis:names:tc:SAML:2.0:assertion"
	claimMail = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
)

// response returns a base64 SAMLResponse with one signed assertion for nameID/email.
func (p *testIdP) response(t *testing.T, audience, acs, nameID, email string) string {
	t.Helper()
	now := time.Now().UTC()
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsSAMLP)
	resp.CreateAttr("xmlns:saml", nsSAML)
	resp.CreateAttr("ID", "_r"+randHex())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	resp.CreateAttr("Destination", acs)
	resp.CreateElement("saml:Issuer").SetText(idpEntity)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	as := resp.CreateElement("saml:Assertion")
	as.CreateAttr("xmlns:saml", nsSAML)
	as.CreateAttr("ID", "_a"+randHex())
	as.CreateAttr("Version", "2.0")
	as.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	as.CreateElement("saml:Issuer").SetText(idpEntity)
	subj := as.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(nameID)
	conf := subj.CreateElement("saml:SubjectConfirmation")
	conf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	data := conf.CreateElement("saml:SubjectConfirmationData")
	data.CreateAttr("NotOnOrAfter", now.Add(10*time.Minute).Format(time.RFC3339))
	data.CreateAttr("Recipient", acs)
	cond := as.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", now.Add(-time.Minute).Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", now.Add(10*time.Minute).Format(time.RFC3339))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)
	authn := as.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", now.Format(time.RFC3339))
	authn.CreateAttr("SessionIndex", "s"+randHex())
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	attr := as.CreateElement("saml:AttributeStatement").CreateElement("saml:Attribute")
	attr.CreateAttr("Name", claimMail)
	attr.CreateElement("saml:AttributeValue").SetText(email)

	sc := dsig.NewDefaultSigningContext(p)
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := sc.SignEnveloped(as)
	if err != nil {
		t.Fatal(err)
	}
	parent := as.Parent()
	for i, c := range parent.ChildElements() {
		if c == as {
			parent.RemoveChildAt(i)
			parent.InsertChildAt(i, signed)
			break
		}
	}
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func spKeypair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sqlite-e2e-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// TestEnterpriseEndToEnd drives SAML SSO and SCIM provisioning through a
// theauth.TheAuth backed by the SQLite adapter only.
func TestEnterpriseEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newStore(t)
	spCert, spKey := spKeypair(t)
	idp := newTestIdP(t)

	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://sp.e2e.test",
		Organizations: &theauth.OrganizationsConfig{},
		SAML:          &theauth.SAMLConfig{SPCertificatePEM: spCert, SPPrivateKeyPEM: spKey},
		SCIM:          &theauth.SCIMConfig{RequireHTTPS: false, MaxPageSize: 100},
	})
	if err != nil {
		t.Fatalf("theauth.New on the sqlite adapter: %v", err)
	}
	t.Cleanup(a.Close)

	owner := mkUser(t, store, "owner@e2e.test")
	org, err := a.CreateOrganization(ctx, "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if role, err := store.OrganizationMemberRole(ctx, org.ID, owner.ID); err != nil || role != "owner" {
		t.Fatalf("owner role = %q, %v", role, err)
	}

	conn, err := a.CreateSAMLConnection(ctx, theauth.SAMLConnectionInput{
		OrganizationID: org.ID,
		IdPEntityID:    idpEntity,
		IdPSSOURL:      "http://idp.e2e.local/sso",
		IdPX509Cert:    idp.certPEM,
		SPEntityID:     "https://sp.e2e.test/saml",
		SPACSURL:       "https://sp.e2e.test/auth/saml/acs",
		AttributeMap:   theauth.DefaultSAMLAttributeMap(),
	})
	if err != nil {
		t.Fatalf("CreateSAMLConnection: %v", err)
	}

	t.Run("SAMLLogin", func(t *testing.T) {
		resp := idp.response(t, conn.SPEntityID, conn.SPACSURL, "saml-user-1", "jit@e2e.test")
		token, sess, err := a.FinishSAMLLogin(ctx, conn.ID, resp, "e2e-ua", "203.0.113.9")
		if err != nil {
			t.Fatalf("FinishSAMLLogin: %v", err)
		}
		if token == "" {
			t.Fatal("empty session token")
		}
		got, err := store.SessionByID(ctx, sess.ID)
		if err != nil || got.ActiveOrganizationID == nil || *got.ActiveOrganizationID != org.ID {
			t.Fatalf("persisted session = %+v, %v", got, err)
		}
		user, err := store.UserByEmail(ctx, "jit@e2e.test")
		if err != nil {
			t.Fatalf("JIT user missing: %v", err)
		}
		if _, err := store.OrganizationMemberRole(ctx, org.ID, user.ID); err != nil {
			t.Fatalf("JIT user not in the organization: %v", err)
		}
		ident, err := store.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, "saml-user-1")
		if err != nil || ident.UserID != user.ID {
			t.Fatalf("identity = %+v, %v", ident, err)
		}
		again := idp.response(t, conn.SPEntityID, conn.SPACSURL, "saml-user-1", "jit@e2e.test")
		if _, _, err := a.FinishSAMLLogin(ctx, conn.ID, again, "", ""); err != nil {
			t.Fatalf("second login: %v", err)
		}
		if n, _ := store.CountUsers(ctx); n != 2 {
			t.Fatalf("users = %d, want owner + one JIT user", n)
		}
	})

	t.Run("SAMLRejectsWrongSigner", func(t *testing.T) {
		rogue := newTestIdP(t)
		resp := rogue.response(t, conn.SPEntityID, conn.SPACSURL, "intruder", "intruder@e2e.test")
		if _, _, err := a.FinishSAMLLogin(ctx, conn.ID, resp, "", ""); err == nil {
			t.Fatal("assertion signed by an unpinned key was accepted")
		}
		if _, err := store.UserByEmail(ctx, "intruder@e2e.test"); err == nil {
			t.Fatal("user was created from a rejected assertion")
		}
	})

	t.Run("SCIMLifecycle", func(t *testing.T) {
		scimToken, rec, err := a.CreateSCIMToken(ctx, org.ID, "okta")
		if err != nil {
			t.Fatalf("CreateSCIMToken: %v", err)
		}
		if len(rec.TokenHash) != 32 || bytes.Contains(rec.TokenHash, []byte(scimToken)) {
			t.Fatalf("token must be stored as a sha256 hash, got %d bytes", len(rec.TokenHash))
		}
		r := chi.NewRouter()
		a.Mount(r)
		srv := httptest.NewServer(r)
		t.Cleanup(srv.Close)

		do := func(method, path, bearer string, body any) (int, map[string]any) {
			t.Helper()
			var rd *bytes.Reader
			if body != nil {
				raw, _ := json.Marshal(body)
				rd = bytes.NewReader(raw)
			} else {
				rd = bytes.NewReader(nil)
			}
			req, _ := http.NewRequest(method, srv.URL+path, rd)
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			req.Header.Set("Content-Type", "application/scim+json")
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			var out map[string]any
			_ = json.NewDecoder(res.Body).Decode(&out)
			return res.StatusCode, out
		}

		if code, _ := do("GET", "/scim/v2/Users", "", nil); code != http.StatusUnauthorized {
			t.Fatalf("no bearer: %d, want 401", code)
		}
		if code, _ := do("GET", "/scim/v2/Users", "not-a-token", nil); code != http.StatusUnauthorized {
			t.Fatalf("bad bearer: %d, want 401", code)
		}

		code, created := do("POST", "/scim/v2/Users", scimToken, map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName":   "scim.user@e2e.test",
			"externalId": "okta-1",
			"name":       map[string]string{"givenName": "Scim", "familyName": "User"},
			"emails":     []map[string]any{{"value": "scim.user@e2e.test", "primary": true}},
			"active":     true,
		})
		if code != http.StatusCreated {
			t.Fatalf("create: %d %v", code, created)
		}
		uid, _ := created["id"].(string)

		if code, list := do("GET", "/scim/v2/Users?filter=externalId%20eq%20%22okta-1%22", scimToken, nil); code != http.StatusOK || list["totalResults"] != float64(1) {
			t.Fatalf("filtered list: %d %v", code, list)
		}

		user, err := store.UserByEmail(ctx, "scim.user@e2e.test")
		if err != nil || user.ID.String() != uid {
			t.Fatalf("stored user = %+v, %v", user, err)
		}
		sessTok := mkSession(t, store, user.ID)

		code, _ = do("PATCH", "/scim/v2/Users/"+uid, scimToken, map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
		})
		if code != http.StatusOK {
			t.Fatalf("deactivate: %d", code)
		}
		if _, err := store.OrganizationMemberRole(ctx, org.ID, user.ID); err == nil {
			t.Fatal("deactivated user is still an organization member")
		}
		if code, _ := do("GET", "/scim/v2/Users/"+uid, scimToken, nil); code != http.StatusNotFound {
			t.Fatalf("deactivated user still visible through SCIM: %d", code)
		}

		t.Run("SessionsAreRevoked", func(t *testing.T) {
			sess, err := store.SessionByTokenHash(ctx, sessTok)
			if err != nil {
				t.Fatal(err)
			}
			if sess.RevokedAt == nil {
				t.Fatal("deactivated user's session is still live")
			}
		})

		if err := a.RevokeSCIMToken(ctx, rec.ID); err != nil {
			t.Fatal(err)
		}
		if code, _ := do("GET", "/scim/v2/Users", scimToken, nil); code != http.StatusUnauthorized {
			t.Fatalf("revoked token: %d, want 401", code)
		}
	})
}

func mkSession(t *testing.T, s *sqlitestore.Store, userID theauth.ULID) []byte {
	t.Helper()
	hash := []byte("e2e-session-" + randHex())
	_, err := s.CreateSession(context.Background(), theauth.Session{
		ID: newID(), UserID: userID, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

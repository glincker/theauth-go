package saml_test

import (
	"context"
	"errors"
	"testing"

	theauth "github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/samltest"
	"github.com/glincker/theauth-go/internal/theauthtest"
	"github.com/glincker/theauth-go/storage/memory"
)

// newSAMLTestAuth wires a TheAuth with Organizations + SAML enabled and
// returns the auth + the underlying memory store. A fresh SP keypair is
// generated for each test so the cert + key never need to be checked in.
func newSAMLTestAuth(t *testing.T) (*theauth.TheAuth, *memory.Store, []byte, []byte) {
	t.Helper()
	store := memory.New()
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://sp.example.test",
		Organizations: &theauth.OrganizationsConfig{},
		SAML: &theauth.SAMLConfig{
			SPCertificatePEM: certPEM,
			SPPrivateKeyPEM:  keyPEM,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store, certPEM, keyPEM
}

func seedSAMLConnection(t *testing.T, a *theauth.TheAuth, store *memory.Store) (theauth.Organization, theauth.SAMLConnection) {
	t.Helper()
	owner := theauthtest.NewUser(t, store, "owner@x.test")
	org, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := a.CreateSAMLConnection(context.Background(), theauth.SAMLConnectionInput{
		OrganizationID: org.ID,
		IdPEntityID:    samltest.IdPEntityID(),
		IdPSSOURL:      samltest.IdPSSOURL(),
		IdPX509Cert:    samltest.IdPCertPEM(),
		SPEntityID:     "https://sp.example.test/saml",
		SPACSURL:       "https://sp.example.test/auth/saml/acs",
		AttributeMap:   theauth.DefaultSAMLAttributeMap(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return org, conn
}

func TestSAMLFindOrCreate_NewUser(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	_, conn := seedSAMLConnection(t, a, store)

	assertion := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	assertion.Email = "new-user@samltest.local"
	assertion.NameID = "saml-new-user"
	resp, err := assertion.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}
	token, sess, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp, "ua", "1.2.3.4")
	if err != nil {
		t.Fatalf("FinishSAMLLogin: %v", err)
	}
	if token == "" {
		t.Fatal("empty session token")
	}
	if sess.ActiveOrganizationID == nil || *sess.ActiveOrganizationID != conn.OrganizationID {
		t.Fatalf("active org not set on session: %+v", sess)
	}
	user, err := store.UserByEmail(context.Background(), "new-user@samltest.local")
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("expected email verified on SAML-created user")
	}
	if _, err := store.OrganizationMemberRole(context.Background(), conn.OrganizationID, user.ID); err != nil {
		t.Fatalf("user not added to org: %v", err)
	}
}

func TestSAMLFindOrCreate_ExistingIdentity(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	_, conn := seedSAMLConnection(t, a, store)
	// First login creates the user + identity.
	a1 := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	resp1, _ := a1.SignAndEncode()
	if _, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp1, "", ""); err != nil {
		t.Fatal(err)
	}
	// Second login with the same NameID should hit branch 1 (existing identity).
	a2 := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	resp2, _ := a2.SignAndEncode()
	if _, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp2, "", ""); err != nil {
		t.Fatalf("second login: %v", err)
	}
	// Only one user should exist.
	if u, _ := store.UserByEmail(context.Background(), a1.Email); u == nil {
		t.Fatal("user not found")
	}
}

func TestSAMLFindOrCreate_EmailFallback(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	org, conn := seedSAMLConnection(t, a, store)
	// Pre-seed a user with the same email but no SAML identity row.
	preexisting := theauthtest.NewUser(t, store, "fallback@samltest.local")
	_ = org

	a1 := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	a1.Email = "fallback@samltest.local"
	a1.NameID = "saml-new-fallback"
	resp, _ := a1.SignAndEncode()
	_, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// User count unchanged
	got, _ := store.UserByEmail(context.Background(), "fallback@samltest.local")
	if got == nil || got.ID != preexisting.ID {
		t.Fatalf("expected reuse of preexisting user, got %+v", got)
	}
	// Identity row exists
	ident, err := store.SAMLIdentityByConnectionAndNameID(context.Background(), conn.ID, "saml-new-fallback")
	if err != nil {
		t.Fatal(err)
	}
	if ident.UserID != preexisting.ID {
		t.Fatalf("identity not linked to preexisting user: %+v", ident)
	}
	// User is now a member of the connection's org
	if _, err := store.OrganizationMemberRole(context.Background(), conn.OrganizationID, preexisting.ID); err != nil {
		t.Fatal("preexisting user not added to org")
	}
}

func TestSAMLRejectsUnsignedAssertion(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	_, conn := seedSAMLConnection(t, a, store)
	a1 := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	a1.SkipSign = true
	resp, _ := a1.SignAndEncode()
	_, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp, "", "")
	if err == nil {
		t.Fatal("expected error on unsigned assertion")
	}
	// crewjam/saml rejects unsigned assertions during ParseXMLResponse, so
	// we wrap with ErrSAMLInvalidAssertion; either that or our explicit
	// ErrSAMLUnsignedAssertion gate is acceptable.
	if !errors.Is(err, theauth.ErrSAMLInvalidAssertion) && !errors.Is(err, theauth.ErrSAMLUnsignedAssertion) {
		t.Fatalf("want unsigned/invalid assertion error, got %v", err)
	}
}

func TestSAMLMissingEmailRejected(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	_, conn := seedSAMLConnection(t, a, store)
	a1 := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	a1.Email = ""
	resp, _ := a1.SignAndEncode()
	_, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp, "", "")
	if !errors.Is(err, theauth.ErrSAMLMissingEmail) {
		t.Fatalf("want ErrSAMLMissingEmail, got %v", err)
	}
}

func TestSAMLMetadataXML(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	_, conn := seedSAMLConnection(t, a, store)
	xmlBytes, err := a.SAMLMetadataXML(context.Background(), conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(xmlBytes) == 0 {
		t.Fatal("empty metadata")
	}
	// Smoke-check: the SP entity ID appears in the XML.
	if !containsString(xmlBytes, conn.SPEntityID) {
		t.Fatalf("metadata does not mention SP entity ID")
	}
}

func TestSAMLConnectionCRUD(t *testing.T) {
	a, store, _, _ := newSAMLTestAuth(t)
	owner := theauthtest.NewUser(t, store, "o@x.test")
	org, _ := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	in := theauth.SAMLConnectionInput{
		OrganizationID: org.ID,
		IdPEntityID:    samltest.IdPEntityID(),
		IdPSSOURL:      samltest.IdPSSOURL(),
		IdPX509Cert:    samltest.IdPCertPEM(),
		SPEntityID:     "https://sp.example.test/saml",
		SPACSURL:       "https://sp.example.test/acs",
	}
	conn, err := a.CreateSAMLConnection(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.IdPSSOURL = "https://idp.example.test/sso-rotated"
	updated, err := a.UpdateSAMLConnection(context.Background(), conn.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if updated.IdPSSOURL != "https://idp.example.test/sso-rotated" {
		t.Fatal("update did not propagate")
	}
	conns, _ := a.ListSAMLConnections(context.Background(), org.ID)
	if len(conns) != 1 {
		t.Fatalf("expected 1, got %d", len(conns))
	}
	if err := a.DeleteSAMLConnection(context.Background(), conn.ID); err != nil {
		t.Fatal(err)
	}
	conns, _ = a.ListSAMLConnections(context.Background(), org.ID)
	if len(conns) != 0 {
		t.Fatalf("expected 0, got %d", len(conns))
	}
}

func containsString(haystack []byte, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return true
		}
	}
	return false
}
